#ifndef P2P_GUARD_ENDPOINT_POLICY_H
#define P2P_GUARD_ENDPOINT_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum { PGNameAbsent, PGNameWait, PGNameFound } PGNameAction;
typedef struct { PGNameAction action; size_t required; } PGNameResult;
bool pg_numeric_address(const char *address);
bool pg_dns_name(const char *host);
bool pg_xunlei_service(const char *host);
PGNameResult pg_web_name(unsigned port, const uint8_t *bytes, size_t size, char host[254]);
#endif
