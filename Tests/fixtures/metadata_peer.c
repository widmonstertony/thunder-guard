/* Live loopback acceptance fixture. Serves only a fixed synthetic metadata record and one four-byte piece. */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static const unsigned char keepalive[4] = {0};
static const char our_ext[] = {20,0,'d','1',':','m','d','1','1',':','u','t','_','m','e','t','a','d','a','t','a','i','5','e','e','e'};
static const char seed_ext[] = "\x14\x00" "d1:md11:ut_metadatai7ee13:metadata_sizei86ee";
static const char request[] = "\x14\x07" "d8:msg_typei0e5:piecei0ee";
// Bencoded info dictionary for fixture.txt, 4 bytes, SHA-1 of the piece
// embedded in the final field. The handshake carries its real info hash.
#define FIXTURE_INFO "d6:lengthi4e4:name11:fixture.txt12:piece lengthi16384e6:pieces20:" \
    "\x75\x06\xc8\x2b\x32\x78\xe4\x11\x3b\x07\x0b\x25\x5e\x1f\x0f\x4f\x5a\xc9\xd4\xac" "e"
static const char reply[] = "\x14\x05" "d8:msg_typei1e5:piecei0e10:total_sizei86ee" FIXTURE_INFO;
static const char info_hash[] = "\x05\xd5\x3f\x6a\x52\xca\x8d\x5e\x42\xc9\x04\x3e\x3a\x33\xfd\xf6\xac\x03\x60\x7c";
_Static_assert(sizeof FIXTURE_INFO - 1 == 86, "metadata length");
static const unsigned char piece[] = {7,0,0,0,0,0,0,0,0,'T','G','0','3'};
static void note(const char *m) { puts(m); fflush(stdout); }
static int transmit(int fd,const void *p,size_t n) { return send(fd,p,n,0)==(ssize_t)n; }
static int read_n(int fd,void *p,size_t n) { return recv(fd,p,n,MSG_WAITALL)==(ssize_t)n; }
static int send_frame(int fd,const void *p,size_t n) {
    uint32_t size=htonl((uint32_t)n); return transmit(fd,&size,4) && transmit(fd,p,n);
}
static int match_frame(int fd,const void *p,size_t n) {
    uint32_t size; unsigned char b[256];
    return n<=sizeof b && read_n(fd,&size,4) && ntohl(size)==n && read_n(fd,b,n) && !memcmp(p,b,n);
}
static int keep(int fd) { unsigned char b[4]; return read_n(fd,b,4) && !memcmp(b,keepalive,4); }
int main(int argc,char **argv) {
    if (argc!=5) return 64;
    signal(SIGPIPE,SIG_IGN);
    alarm(10);
    int fd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(argv[1]))};
    if (inet_pton(AF_INET,"127.0.0.1",&a.sin_addr)!=1) return 64;
    if (!strcmp(argv[2],"listen")) {
        int one=1;
        setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
        if (bind(fd,(struct sockaddr*)&a,sizeof a)||listen(fd,1)) {perror("listen"); return 65;}
        socklen_t len=sizeof a;
        if (getsockname(fd,(struct sockaddr*)&a,&len)) return 65;
        printf("listener ready %u\n",ntohs(a.sin_port));
        fflush(stdout);
        int client=accept(fd,NULL,NULL);
        close(fd); fd=client;
        if (fd<0) return 65;
    } else if (connect(fd,(struct sockaddr*)&a,sizeof a)) {perror("connect"); return 65;}
    socklen_t peerlen=sizeof a;
    if (getpeername(fd,(struct sockaddr*)&a,&peerlen)) return 65;
    printf("remote port %u\n",ntohs(a.sin_port));
    fflush(stdout);
    struct timeval timeout={.tv_sec=4};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);
    int seed=!strcmp(argv[3],"seed");
    unsigned char hs[68]="\023BitTorrent protocol", incoming[68];
    hs[25]=0x10;
    memcpy(hs+28,info_hash,sizeof info_hash-1);
    if (!transmit(fd,hs,sizeof hs)||!read_n(fd,incoming,sizeof incoming)||memcmp(hs,incoming,48)) {note("handshake missing");return 66;}
    if (seed) {
        if (!send_frame(fd,seed_ext,sizeof seed_ext-1)||!match_frame(fd,our_ext,sizeof our_ext)||
            !match_frame(fd,request,sizeof request-1)||!send_frame(fd,reply,sizeof reply-1)||!keep(fd)) {
            note("metadata negotiation failed"); return 67;
        }
        note("metadata receiver confirmed");
    } else {
        if (!send_frame(fd,our_ext,sizeof our_ext)||!match_frame(fd,seed_ext,sizeof seed_ext-1)||
            !send_frame(fd,request,sizeof request-1)||!match_frame(fd,reply,sizeof reply-1)||
            !transmit(fd,keepalive,4)) {
            note("metadata negotiation failed"); return 67;
        }
        note("metadata verified");
    }
    if (!strcmp(argv[4],"send")) {
        if (!send_frame(fd,piece,sizeof piece)) {note("file write rejected");return 68;}
        if (!keep(fd)) {note("no file receipt");return 69;}
        note("file receipt confirmed");
    } else {
        if (!match_frame(fd,piece,sizeof piece)) {note("no file bytes");return 70;}
        note("received file bytes");
        transmit(fd,keepalive,4);
    }
    close(fd);return 0;
}
