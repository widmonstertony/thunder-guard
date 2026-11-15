#ifndef THUNDER_PEER_WIRE_H
#define THUNDER_PEER_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TG_HANDSHAKE_SIZE 68
#define TG_MAX_FRAME (16384u + 256u)
#define TG_MAX_CLIENT_HELLO 8192
#define TG_MAX_DHT 1500

typedef enum {
    TGWait, TGPass, TGDropUnknown, TGDropFile
} TGAction;

typedef struct {
    TGAction action;
    size_t count;  // bytes to pass, or the total prefix still needed at this offset
} TGDecision;

typedef struct {
    bool handshake;
    bool extended;
    uint8_t receiveID;
    uint32_t metadataSize;
    uint64_t offset;
} TGPeerDirection;

typedef struct {
    TGPeerDirection directions[2]; // 0: outbound; 1: inbound
    uint8_t infoHash[20];
    uint8_t pending[32];          // 256 chunks of up to 16 KiB each
} TGPeerSession;

typedef struct {
    uint8_t transaction[8];
    size_t length;
} TGDHTRequest;

// Callers must pass precisely decision.count bytes and peek again on TGPass.
TGDecision tg_peer_data(TGPeerSession *session, bool inbound, uint64_t offset,
                        const uint8_t *bytes, size_t length);
TGDecision tg_tls_name(const uint8_t *bytes, size_t length, char host[254]);
TGDecision tg_http_name(const uint8_t *bytes, size_t length, char host[254]);
bool tg_dht_query(const uint8_t *bytes, size_t length, TGDHTRequest *request);
bool tg_dht_reply(const uint8_t *bytes, size_t length, const TGDHTRequest *request);

#endif
