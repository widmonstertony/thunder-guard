#include "PeerClassifier.h"
#include <string.h>

static PGDecision result(PGAction action, size_t count) { return (PGDecision){action, count}; }

PGDecision pg_classify(PGStream *s, bool inbound, uint64_t offset, const uint8_t *b, size_t n) {
    const PGDecision unknown = result(PGUnidentified, 0);
    if (offset != s->offset) return unknown;
    size_t frame;
    if (!s->identified) {
        static const char bt[] = "\023BitTorrent protocol";
        size_t prefix = sizeof bt - 1;
        if (n && memcmp(b, bt, n < prefix ? n : prefix)) return unknown;
        // Check the protocol string as soon as it can be seen. Don't wait for 68
        // bytes from a short request issued by an unrelated protocol.
        if (n < prefix) return result(PGPeek, prefix);
        if (n < 68) return result(PGPeek, 68);
        s->identified = true;
        frame = 68;
    } else {
        if (n < 4) return result(PGPeek, 4);
        const uint32_t length = (uint32_t)b[0]<<24 | (uint32_t)b[1]<<16 | (uint32_t)b[2]<<8 | b[3];
        if (length && n < 5) return result(PGPeek, 5);
        // Message ID 6 is a file request; ID 7 carries file data. BEP 9
        // metadata uses the extended message (ID 20), never ID 6 or 7.
        if (length == 13 && b[4] == 6) return result(inbound ? PGBlockUpload : PGBlockDownload, 0);
        if (length >= 10 && b[4] == 7) return result(inbound ? PGBlockDownload : PGBlockUpload, 0);
        // Keep memory bounded even on broken peers. Do not label malformed
        // traffic as a file transfer. Future encrypted transports need their own classifier.
        if (length > 1024 * 1024) return unknown;
        frame = 4 + length;
        if (n < frame) return result(PGPeek, frame);
    }
    if (offset > UINT64_MAX - frame) return unknown;
    s->offset += frame;
    return result(PGPass, frame);
}
