#include "EndpointPolicy.h"
#include <arpa/inet.h>
#include <string.h>
#include <strings.h>

static bool alnum_ascii(unsigned char c) {
    return (c >= '0' && c <= '9') || ((c | 32) >= 'a' && (c | 32) <= 'z');
}

bool pg_numeric_address(const char *address) {
    if (!address || !*address) return false;
    char text[INET6_ADDRSTRLEN];
    if (*address == '[') ++address;
    size_t len = strcspn(address, "%]");
    if (!len || len >= sizeof text) return false;
    memcpy(text, address, len); text[len] = 0;
    struct in6_addr result;
    return inet_pton(AF_INET, text, &result) == 1 || inet_pton(AF_INET6, text, &result) == 1;
}

bool pg_dns_name(const char *host) {
    if (!host || pg_numeric_address(host)) return false;
    size_t len = strlen(host), label = 0;
    if (len && host[len-1] == '.') --len;
    if (!len || len > 253) return false;
    bool dot = false, letter = false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = host[i];
        if (c == '.') {
            if (!label || host[i-1] == '-') return false;
            label = 0;
            dot = true;
        } else {
            if ((!alnum_ascii(c) && c != '-') || (!label && c == '-') || ++label > 63) return false;
            if ((c | 32) >= 'a' && (c | 32) <= 'z') letter = true;
        }
    }
    return dot && letter && label && host[len-1] != '-';
}

bool pg_xunlei_service(const char *host) {
    if (!pg_dns_name(host)) return false;
    size_t len = strlen(host);
    if (host[len-1] == '.') --len;
    const char *suffix = "xunlei.com", *cdn = "xfile2.a.88cdn.com";
    size_t n = strlen(suffix);
    return (len >= n && (len == n || host[len-n-1] == '.') && !strncasecmp(host+len-n, suffix, n)) ||
           (len == strlen(cdn) && !strncasecmp(host, cdn, len));
}

static PGNameResult answer(PGNameAction action, size_t required) { return (PGNameResult){action, required}; }
static unsigned u16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }
static unsigned u24(const uint8_t *p) { return (unsigned)p[0] << 16 | (unsigned)p[1] << 8 | p[2]; }

static bool copy_name(char host[254], const uint8_t *s, size_t n) {
    if (!n || n >= 254 || memchr(s, 0, n)) return false;
    memcpy(host, s, n);
    host[n] = 0;
    return pg_dns_name(host);
}

// ClientHello handshake bytes without TLS record headers.
static bool client_name(const uint8_t *h, size_t n, char host[254]) {
    size_t cursor = 34;
    if (n <= cursor || h[0] != 3) return false;
    cursor += (size_t)h[cursor] + 1;
    if (cursor + 2 > n) return false;
    unsigned suites = u16(h + cursor);
    if (!suites || suites % 2) return false;
    cursor += 2 + suites;
    if (cursor >= n) return false;
    cursor += (size_t)h[cursor] + 1;
    if (cursor + 2 > n || u16(h + cursor) != n-cursor-2) return false;
    cursor += 2;
    bool found = false;
    while (cursor < n) {
        if (cursor + 4 > n) return false;
        unsigned type = u16(h + cursor), length = u16(h + cursor + 2);
        cursor += 4;
        if (length > n - cursor) return false;
        if (type == 0) {
            const uint8_t *s = h + cursor;
            if (found || length < 6 || u16(s) != length-2 || s[2] != 0 ||
                u16(s+3) != length-5 || !copy_name(host, s+5, length-5)) return false;
            found = true;
        }
        cursor += length;
    }
    return found;
}

static PGNameResult tls(const uint8_t *b, size_t n, char host[254]) {
    const PGNameResult no = {PGNameAbsent, 0};
    uint8_t hello[16384];
    size_t out = 0, index = 0;
    for (unsigned records = 0; records < 8; ++records) {
        if (index < n && b[index] != 22) return no;
        if (n-index < 5) return answer(PGNameWait, index + 5);
        if (b[index+1] != 3 || b[index+2] > 3) return no;
        unsigned record = u16(b + index + 3);
        index += 5;
        if (!record || record > sizeof hello-out) return no;
        if (n-index < record) return answer(PGNameWait, index + record);
        memcpy(hello + out, b + index, record);
        out += record;
        index += record;
        if (hello[0] != 1) return no;
        if (out < 4) continue;
        size_t expected = u24(hello + 1) + 4u;
        if (expected > sizeof hello) return no;
        if (out >= expected) return client_name(hello+4, expected-4, host) ? answer(PGNameFound, 0) : no;
    }
    return no;
}

static PGNameResult http(const uint8_t *bytes, size_t n, char host[254]) {
    const PGNameResult no = {PGNameAbsent, 0};
    const char *methods[] = {"GET ", "HEAD ", "POST ", "OPTIONS ", "PUT ", "PATCH ", "DELETE "};
    bool request = false;
    for (size_t i = 0; i < sizeof methods/sizeof *methods; ++i) {
        size_t m = strlen(methods[i]);
        if (memcmp(bytes, methods[i], n < m ? n : m)) continue;
        if (n <= m) return answer(PGNameWait, m + 1);
        if (bytes[m] == '/') request = true;
    }
    if (!request) return no;
    size_t limit = n < 8192 ? n : 8192;
    size_t offset = 0;
    bool found = false;
    while (offset < limit) {
        size_t end = offset;
        while (end + 1 < limit && memcmp(bytes+end, "\r\n", 2)) ++end;
        if (end + 1 >= limit) break;
        if (!offset) {
            if (end < 10 || memcmp(bytes + end - 9, " HTTP/1.", 8) || (bytes[end-1] != '0' && bytes[end-1] != '1')) return no;
        } else if (end == offset) {
            return found ? answer(PGNameFound, 0) : no;
        } else if (end-offset >= 5 && !strncasecmp((const char *)bytes+offset, "Host:", 5)) {
            size_t start = offset + 5, stop = end;
            while (start < stop && (bytes[start] == ' ' || bytes[start] == '\t')) ++start;
            while (stop > start && (bytes[stop-1] == ' ' || bytes[stop-1] == '\t')) --stop;
            if (stop-start > 3 && !memcmp(bytes+stop-3, ":80", 3)) stop -= 3;
            if (found || !copy_name(host, bytes+start, stop-start)) return no;
            found = true;
        } else if (bytes[offset] == ' ' || bytes[offset] == '\t') {
            return no; // reject folded/ambiguous headers
        }
        offset = end + 2;
    }
    return n >= 8192 ? no : answer(PGNameWait, n+1);
}

PGNameResult pg_web_name(unsigned port, const uint8_t *bytes, size_t size, char host[254]) {
    host[0] = 0;
    if (!size) return answer(PGNameWait, 1);
    if (port == 443) return tls(bytes, size, host);
    if (port == 80) return http(bytes, size, host);
    return answer(PGNameAbsent, 0);
}
