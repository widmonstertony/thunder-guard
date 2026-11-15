#include "EndpointPolicy.h"
#include <assert.h>
#include <string.h>

static void set16(uint8_t *p, size_t n) { p[0] = n >> 8; p[1] = n; }

static size_t clienthello(uint8_t *out, const char *server) {
    size_t n = 43, length = strlen(server);
    memset(out, 0, 256);
    out[0] = 22; out[1] = 3; out[2] = 1; out[5] = 1; out[9] = 3; out[10] = 3;
    out[n++] = 0;
    set16(out + n, 2); n += 2;
    out[n++] = 0x13; out[n++] = 1; out[n++] = 1; out[n++] = 0;
    set16(out + n, length + 9); n += 2;
    set16(out + n, 0); n += 2;
    set16(out + n, length + 5); n += 2;
    set16(out + n, length + 3); n += 2;
    out[n++] = 0;
    set16(out + n, length); n += 2;
    memcpy(out + n, server, length); n += length;
    set16(out + 3, n-5); set16(out + 7, n-9);
    return n;
}

int main(void) {
    char host[254];
    assert(pg_numeric_address("116.132.223.85"));
    assert(pg_numeric_address("[fe80::12%en1]"));
    assert(pg_numeric_address("::ffff:192.0.2.10"));
    assert(!pg_dns_name("116.132.223.85"));
    assert(!pg_dns_name("xunlei.com.."));
    assert(!pg_dns_name("-xunlei.com"));
    assert(pg_xunlei_service("vod0781-aliyun04-vip-lixian.xunlei.com"));
    assert(pg_xunlei_service("XUNLEI.COM."));
    assert(pg_xunlei_service("xfile2.a.88cdn.com"));
    assert(!pg_xunlei_service("xunlei.com.attacker.example"));
    assert(!pg_xunlei_service("notxunlei.com"));
    const uint8_t login[] = "POST /login HTTP/1.1\r\nHost: login.xunlei.com\r\nContent-Length: 6\r\n\r\nfixture";
    const uint8_t duplicate[] = "GET / HTTP/1.1\r\nHost: xunlei.com\r\nHost: other.example\r\n\r\n";
    const uint8_t raw[] = "GET / HTTP/1.1\r\nHost: 192.0.2.50\r\n\r\n";
    assert(pg_web_name(80, login, 2, host).action == PGNameWait);
    assert(pg_web_name(80, login, sizeof login - 1, host).action == PGNameFound && !strcmp(host, "login.xunlei.com"));
    assert(pg_web_name(80, duplicate, sizeof duplicate - 1, host).action == PGNameAbsent);
    assert(pg_web_name(80, raw, sizeof raw - 1, host).action == PGNameAbsent);
    uint8_t hello[256], split[256];
    size_t n = clienthello(hello, "vod3429-aliyun04-vip-lixian.xunlei.com");
    for (size_t i = 0; i < n; ++i) assert(pg_web_name(443, hello, i, host).action == PGNameWait);
    assert(pg_web_name(443, hello, n, host).action == PGNameFound && pg_xunlei_service(host));
    memcpy(split, hello, 28); set16(split+3, 23);
    memcpy(split+28, hello, 5); set16(split+31, n-28);
    memcpy(split+33, hello+28, n-28);
    assert(pg_web_name(443, split, n+4, host).action == PGNameWait);
    assert(pg_web_name(443, split, n+5, host).action == PGNameFound && pg_xunlei_service(host));
    n = clienthello(hello, "192.0.2.50");
    assert(pg_web_name(443, hello, n, host).action == PGNameAbsent);
    const uint8_t peer[] = "\023BitTorrent protocol";
    assert(pg_web_name(443, peer, sizeof peer, host).action == PGNameAbsent);
    assert(pg_web_name(1500, peer, sizeof peer, host).action == PGNameAbsent);
}
