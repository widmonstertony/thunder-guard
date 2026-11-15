#include "ThunderPeerWire.h"
#include <limits.h>
#include <string.h>

typedef struct { const uint8_t *p; size_t n; } Slice;

static TGDecision verdict(TGAction action, size_t count) { return (TGDecision){action, count}; }
static bool is(Slice s, const char *str) { return strlen(str) == s.n && !memcmp(s.p, str, s.n); }
static bool digit(uint8_t c) { return c >= '0' && c <= '9'; }

static bool decimal(Slice *s, uint32_t *value)
{
    if (!s->n || !digit(*s->p)) return false;
    if (s->n > 1 && *s->p == '0' && digit(s->p[1])) return false;
    uint32_t n = 0;
    while (s->n && digit(*s->p)) {
        uint8_t d = *s->p - '0';
        if (n > (UINT32_MAX - d) / 10) return false;
        n = n * 10 + d;
        ++s->p;
        --s->n;
    }
    *value = n;
    return true;
}

static bool eat(Slice *s, uint8_t c)
{
    if (!s->n || *s->p != c) return false;
    ++s->p;
    --s->n;
    return true;
}

static bool take(Slice *s, size_t n, Slice *out)
{
    if (s->n < n) return false;
    *out = (Slice){s->p, n};
    s->p += n;
    s->n -= n;
    return true;
}

static bool string(Slice *s, Slice *out)
{
    uint32_t n;
    return decimal(s, &n) && eat(s, ':') && take(s, n, out);
}

static bool number(Slice *s, uint32_t *out)
{
    return eat(s, 'i') && decimal(s, out) && eat(s, 'e');
}

// Strict ordering rejects duplicate keys and ambiguous interpretations.
static bool key(Slice *s, Slice *previous)
{
    Slice current;
    if (!string(s, &current) || !current.n) return false;
    if (previous->p) {
        int diff = memcmp(previous->p, current.p, previous->n < current.n ? previous->n : current.n);
        if (diff > 0 || (diff == 0 && previous->n >= current.n)) return false;
    }
    *previous = current;
    return true;
}

static bool skip(Slice *s, unsigned depth)
{
    Slice item = {0};
    uint32_t n;
    if (!depth || !s->n) return false;
    if (eat(s, 'l')) {
        while (!eat(s, 'e')) if (!skip(s, depth - 1)) return false;
        return true;
    }
    if (eat(s, 'd')) {
        while (!eat(s, 'e')) if (!key(s, &item) || !skip(s, depth - 1)) return false;
        return true;
    }
    return digit(*s->p) ? string(s, &item) : number(s, &n);
}

static bool extension_handshake(Slice body, uint8_t *id, uint32_t *size)
{
    Slice name = {0}, ext = {0};
    uint64_t seen[4] = {0};
    *id = 0;
    *size = 0;
    if (!eat(&body, 'd')) return false;
    while (!eat(&body, 'e')) {
        if (!key(&body, &name)) return false;
        if (is(name, "m")) {
            if (!eat(&body, 'd')) return false;
            while (!eat(&body, 'e')) {
                uint32_t n;
                if (!key(&body, &ext) || !number(&body, &n) || n > UINT8_MAX) return false;
                if (n) {
                    uint64_t bit = UINT64_C(1) << (n % 64);
                    if (seen[n / 64] & bit) return false;
                    seen[n / 64] |= bit;
                }
                if (is(ext, "ut_metadata")) *id = (uint8_t)n;
            }
        } else if (is(name, "metadata_size")) {
            if (!number(&body, size) || *size > 256u * 16384u) return false;
        } else if (!skip(&body, 4)) {
            return false;
        }
    }
    return body.n == 0;
}

static bool metadata(TGPeerSession *s, bool inbound, Slice body)
{
    uint32_t kind = UINT32_MAX, piece = UINT32_MAX, total = 0;
    Slice name = {0};
    if (!eat(&body, 'd')) return false;
    while (!eat(&body, 'e')) {
        if (!key(&body, &name)) return false;
        if (is(name, "msg_type")) {
            if (!number(&body, &kind)) return false;
        } else if (is(name, "piece")) {
            if (!number(&body, &piece)) return false;
        } else if (is(name, "total_size")) {
            if (!number(&body, &total) || !total) return false;
        } else return false;
    }
    const uint32_t size = s->directions[1].metadataSize; // size advertised by remote
    if (piece >= 256 || !size || piece * 16384u >= size) return false;
    uint8_t bit = 1u << (piece % 8);
    uint8_t *pending = &s->pending[piece / 8];
    if (!inbound) { // only Thunder's requests; never serve metadata to remote peers
        if (kind != 0 || total || body.n || (*pending & bit)) return false;
        *pending |= bit;
        return true;
    }
    if (!(*pending & bit)) return false;
    const uint32_t remaining = size - piece * 16384u;
    if (kind == 1) {
        if (total != size || body.n != (remaining < 16384u ? remaining : 16384u)) return false;
    } else if (kind != 2 || total || body.n) return false;
    *pending &= (uint8_t)~bit;
    return true;
}

TGDecision tg_peer_data(TGPeerSession *s, bool inbound, uint64_t offset,
                        const uint8_t *b, size_t len)
{
    TGPeerDirection *d = &s->directions[inbound], *other = &s->directions[!inbound];
    const TGDecision bad = verdict(TGDropUnknown, 0);
    if (offset != d->offset) return bad;
    size_t pass;
    if (!d->handshake) {
        static const char prefix[] = "\023BitTorrent protocol";
        size_t prefixLength = sizeof prefix - 1;
        size_t seen = len < prefixLength ? len : prefixLength;
        if (seen && memcmp(b, prefix, seen)) return bad;
        if (len < TG_HANDSHAKE_SIZE) return verdict(TGWait, TG_HANDSHAKE_SIZE);
        if (!(b[25] & 0x10)) return bad;
        if (other->handshake && memcmp(s->infoHash, b + 28, 20)) return bad;
        memcpy(s->infoHash, b + 28, 20);
        d->handshake = true;
        pass = TG_HANDSHAKE_SIZE;
    } else {
        if (len < 4) return verdict(TGWait, 4);
        uint32_t n = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        if (n > TG_MAX_FRAME - 4) return bad;
        pass = 4 + n;
        if (n) {
            if (len < 5) return verdict(TGWait, 5);
            const uint8_t id = b[4];
            if (id >= 6 && id <= 8) return verdict(TGDropFile, 0);
            // Only bounded control messages and BEP 10.
            if ((id <= 3 && n == 1) || (id == 4 && n == 5) ||
                (id == 9 && n == 3) || // BEP 5 DHT port advertisement
                ((id == 14 || id == 15) && n == 1)) {
                if (len < pass) return verdict(TGWait, pass);
            } else if (id == 5 && n >= 2 && n <= 4097) {
                // Existing peers often send a bitfield before extension negotiation.
                if (len < pass) return verdict(TGWait, pass);
            } else if (id == 20 && n > 2) {
                if (len < 6) return verdict(TGWait, 6);
                uint8_t ext = b[5];
                if ((ext == 0 && (n > 2048 || d->extended)) ||
                    (ext != 0 && (!other->handshake || !d->extended || ext != other->receiveID))) return bad;
                if (len < pass) return verdict(TGWait, pass);
                Slice body = {b + 6, n - 2};
                if (ext == 0) {
                    if (!extension_handshake(body, &d->receiveID, &d->metadataSize)) return bad;
                    d->extended = true;
                } else if (!metadata(s, inbound, body)) return bad;
            } else return bad;
        }
    }
    if (UINT64_MAX - d->offset < pass) return bad;
    d->offset += pass;
    return verdict(TGPass, pass);
}

static bool uint16(Slice *s, size_t *v)
{
    Slice b;
    if (!take(s, 2, &b)) return false;
    *v = (size_t)b.p[0] * 256 + b.p[1];
    return true;
}

static bool copy_hostname(Slice name, char host[254])
{
    if (!name.n || name.n > 253) return false;
    for (size_t i = 0; i < name.n; ++i) {
        uint8_t c = name.p[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (!digit(c) && !(c >= 'a' && c <= 'z') && c != '.' && c != '-') return false;
        host[i] = (char)c;
    }
    host[name.n] = '\0';
    return true;
}

TGDecision tg_tls_name(const uint8_t *b, size_t len, char host[254])
{
    const TGDecision bad = verdict(TGDropUnknown, 0);
    if (len && b[0] != 22) return bad;
    if (len < 5) return verdict(TGWait, 5);
    if (b[1] != 3 || b[2] > 3) return bad;
    size_t record = (size_t)b[3] * 256 + b[4];
    if (record < 43 || record > TG_MAX_CLIENT_HELLO - 5) return bad;
    if (len < record + 5) return verdict(TGWait, record + 5);
    // One complete initial TLS ClientHello. Never scan arbitrarily for a hostname.
    if (b[5] != 1 || b[6] || (size_t)b[7] * 256 + b[8] != record - 4) return bad;
    Slice s = {b + 9, record - 4}, tmp, extensions;
    size_t count, type;
    if (!take(&s, 34, &tmp) || !s.n) return bad;
    count = *s.p;
    if (!take(&s, count + 1, &tmp) || !uint16(&s, &count) || !count || (count % 2) ||
        !take(&s, count, &tmp) || !s.n) return bad;
    count = *s.p;
    if (!take(&s, count + 1, &tmp) || !uint16(&s, &count) || !take(&s, count, &extensions) || s.n) return bad;
    bool found = false;
    while (extensions.n) {
        if (!uint16(&extensions, &type) || !uint16(&extensions, &count) ||
            !take(&extensions, count, &tmp)) return bad;
        if (type != 0) continue;
        if (found || !uint16(&tmp, &count) || count != tmp.n || !eat(&tmp, 0) ||
            !uint16(&tmp, &count) || count != tmp.n || !copy_hostname(tmp, host)) return bad;
        found = true;
    }
    return found ? verdict(TGPass, record + 5) : bad;
}

static bool match_prefix(Slice *s, const char *prefix)
{
    size_t n = strlen(prefix);
    Slice ignored;
    return s->n >= n && !memcmp(s->p, prefix, n) && take(s, n, &ignored);
}

TGDecision tg_http_name(const uint8_t *b, size_t len, char host[254])
{
    const TGDecision bad = verdict(TGDropUnknown, 0);
    size_t end = 0, limit = len < 4096 ? len : 4096;
    for (size_t i = 0; i + 4 <= limit; ++i) {
        if (!memcmp(b + i, "\r\n\r\n", 4)) { end = i + 4; break; }
    }
    if (!end) return len < 4096 ? verdict(TGWait, len + 1) : bad;
    Slice header = {b, end}, line, field;
    if ((!match_prefix(&header, "GET ") && !match_prefix(&header, "HEAD ")) ||
        !header.n || header.p[0] != '/') return bad;
    bool first = true, found = false;
    while (header.n) {
        size_t n = 0;
        while (n + 1 < header.n && !(header.p[n] == '\r' && header.p[n + 1] == '\n')) {
            if (header.p[n] < 32 || header.p[n] > 126) return bad;
            ++n;
        }
        if (n + 1 >= header.n || !take(&header, n, &line) || !eat(&header, '\r') || !eat(&header, '\n')) return bad;
        if (first) {
            first = false;
            if (line.n < 10 || memcmp(line.p + line.n - 9, " HTTP/1.", 8) ||
                (line.p[line.n - 1] != '0' && line.p[line.n - 1] != '1')) return bad;
        } else if (!line.n) {
            return found && !header.n ? verdict(TGPass, end) : bad;
        } else {
            n = 0;
            while (n < line.n && line.p[n] != ':') {
                uint8_t c = line.p[n];
                if (!(digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-')) return bad;
                ++n;
            }
            if (!n || !take(&line, n, &field) || !eat(&line, ':')) return bad;
            if (field.n != 4 || (field.p[0] | 32) != 'h' || (field.p[1] | 32) != 'o' ||
                (field.p[2] | 32) != 's' || (field.p[3] | 32) != 't') continue;
            while (eat(&line, ' ')) {}
            while (line.n && line.p[line.n - 1] == ' ') --line.n;
            if (line.n > 3 && !memcmp(line.p + line.n - 3, ":80", 3)) line.n -= 3;
            if (found || !copy_hostname(line, host)) return bad;
            found = true;
        }
    }
    return bad;
}

static bool fixed_string(Slice *s, size_t min, size_t max)
{
    Slice str;
    return string(s, &str) && str.n >= min && str.n <= max;
}

static bool compact_nodes(Slice *s, size_t width)
{
    Slice str;
    return string(s, &str) && str.n % width == 0 && str.n / width <= 32;
}

static bool dht_args(Slice *s, bool reply, unsigned *shape)
{
    Slice name = {0};
    *shape = 0;
    if (!eat(s, 'd')) return false;
    while (!eat(s, 'e')) {
        if (!key(s, &name)) return false;
        if (is(name, "id")) {
            if (!fixed_string(s, 20, 20)) return false;
            *shape |= 1;
        } else if (!reply && is(name, "target")) {
            if (!fixed_string(s, 20, 20)) return false;
            *shape |= 2;
        } else if (!reply && is(name, "info_hash")) {
            if (!fixed_string(s, 20, 20)) return false;
            *shape |= 4;
        } else if (!reply && is(name, "want")) {
            Slice value;
            unsigned count = 0;
            if (!eat(s, 'l')) return false;
            while (!eat(s, 'e'))
                if (++count > 2 || !string(s, &value) || (!is(value, "n4") && !is(value, "n6"))) return false;
            *shape |= 8;
        } else if (reply && is(name, "nodes")) {
            if (!compact_nodes(s, 26)) return false;
        } else if (reply && is(name, "nodes6")) {
            if (!compact_nodes(s, 38)) return false;
        } else if (reply && is(name, "token")) {
            if (!fixed_string(s, 1, 64)) return false;
        } else if (reply && is(name, "values")) {
            unsigned count = 0;
            Slice address;
            if (!eat(s, 'l')) return false;
            while (!eat(s, 'e'))
                if (++count > 64 || !string(s, &address) || (address.n != 6 && address.n != 18)) return false;
        } else return false;
    }
    return (*shape & 1) != 0;
}

static bool dht_packet(Slice s, bool reply, Slice *transaction)
{
    if (!s.n || s.n > TG_MAX_DHT || !eat(&s, 'd')) return false;
    Slice name = {0}, type = {0}, method = {0}, address;
    unsigned shape = 0;
    *transaction = (Slice){0};
    while (!eat(&s, 'e')) {
        if (!key(&s, &name)) return false;
        if ((!reply && is(name, "a")) || (reply && is(name, "r"))) {
            if (!dht_args(&s, reply, &shape)) return false;
        } else if (!reply && is(name, "q")) {
            if (!string(&s, &method)) return false;
        } else if (is(name, "t")) {
            if (!string(&s, transaction) || !transaction->n || transaction->n > 8) return false;
        } else if (is(name, "y")) {
            if (!string(&s, &type)) return false;
        } else if (is(name, "v")) {
            if (!fixed_string(&s, 1, 8)) return false;
        } else if (is(name, "ip")) {
            if (!string(&s, &address) || (address.n != 6 && address.n != 18)) return false;
        } else if (is(name, "ro")) {
            uint32_t readOnly;
            if (!number(&s, &readOnly) || readOnly > 1) return false;
        } else return false;
    }
    if (s.n || !transaction->n || !(shape & 1) || !is(type, reply ? "r" : "q")) return false;
    if (reply) return true;
    shape &= ~8u;
    return (shape == 1 && is(method, "ping")) ||
           (shape == 3 && is(method, "find_node")) ||
           (shape == 5 && is(method, "get_peers"));
}

bool tg_dht_query(const uint8_t *bytes, size_t length, TGDHTRequest *request)
{
    Slice tx;
    if (!dht_packet((Slice){bytes, length}, false, &tx)) return false;
    memcpy(request->transaction, tx.p, tx.n);
    request->length = tx.n;
    return true;
}

bool tg_dht_reply(const uint8_t *bytes, size_t length, const TGDHTRequest *request)
{
    Slice tx;
    return request->length && dht_packet((Slice){bytes, length}, true, &tx) &&
           tx.n == request->length && !memcmp(tx.p, request->transaction, tx.n);
}
