#ifndef P2P_GUARD_PEER_CLASSIFIER_H
#define P2P_GUARD_PEER_CLASSIFIER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { PGPeek, PGPass, PGUnidentified, PGBlockUpload, PGBlockDownload } PGAction;
typedef struct { PGAction action; size_t count; } PGDecision;
typedef struct { uint64_t offset; bool identified; } PGStream;
// Calls at the same offset may repeat as the prefix grows. Advance only on PGPass.
PGDecision pg_classify(PGStream *, bool inbound, uint64_t offset, const uint8_t *, size_t);
#endif
