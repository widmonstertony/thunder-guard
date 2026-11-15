#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#include <assert.h>
#import <objc/runtime.h>

#define main p2p_guard_entry
#include "Provider.m"
#undef main

@interface FakeSocket : NSObject
@property NSUUID *identifier;
@property NWHostEndpoint *remoteEndpoint;
@property nw_endpoint_t remoteFlowEndpoint;
@property NSString *remoteHostname;
@property NSURL *URL;
@property NETrafficDirection direction;
@property int socketType;
@property int socketProtocol;
@property NSData *sourceAppAuditToken;
@property NSData *sourceProcessAuditToken;
@end
@implementation FakeSocket
- (BOOL)isKindOfClass:(Class)target {
    return target == NEFilterSocketFlow.class || [super isKindOfClass:target];
}
@end

@interface FixtureProvider : PGFilterProvider
@property NEFilterProviderConfiguration *config;
@property NSString *processPath;
@end
@implementation FixtureProvider
- (NEFilterProviderConfiguration *)filterConfiguration { return self.config; }
- (NSString *)thunderPath:(NSData *)token { return self.processPath; }
- (NSSet<NSString *> *)addressesForName:(NSString *)name { return [NSSet setWithObject:@"192.0.2.80"]; }
@end

static NEFilterSocketFlow *flow(NSString *address, NSString *port, NSString *name) {
    FakeSocket *f = [FakeSocket new];
    f.identifier = [NSUUID UUID];
    if (address && port) f.remoteEndpoint = [NWHostEndpoint endpointWithHostname:address port:port];
    f.remoteHostname = name;
    f.direction = NETrafficDirectionOutbound;
    f.socketType = SOCK_STREAM;
    f.socketProtocol = IPPROTO_TCP;
    return (NEFilterSocketFlow *)f;
}

static NSData *frame(NSData *payload) {
    uint32_t len = htonl((uint32_t)payload.length);
    NSMutableData *result = [NSMutableData dataWithBytes:&len length:sizeof len];
    [result appendData:payload];
    return result;
}

static NSData *ascii(NSString *text) { return [text dataUsingEncoding:NSASCIIStringEncoding]; }

static NSData *extended(unsigned char id, NSString *text) {
    unsigned char header[] = { 20, id };
    NSMutableData *payload = [NSMutableData dataWithBytes:header length:sizeof header];
    [payload appendData:ascii(text)];
    return frame(payload);
}

static NEFilterDataVerdict *step(FixtureProvider *guard, NEFilterSocketFlow *socket, BOOL incoming, NSUInteger off, NSData *data) {
    return incoming ? [guard handleInboundDataFromFlow:socket readBytesStartOffset:off readBytes:data] :
        [guard handleOutboundDataFromFlow:socket readBytesStartOffset:off readBytes:data];
}

static NEFilterDataVerdict *pass(NSUInteger count) {
    return [NEFilterDataVerdict dataVerdictWithPassBytes:count peekBytes:1];
}

static void same(NSObject *actual, NSObject *expected) {
    if (!actual || ![actual.description isEqualToString:expected.description]) {
        NSLog(@"Unexpected verdict: %@; expected: %@", actual, expected);
        abort();
    }
}

int main(void) {
    @autoreleasepool {
        auditLog = OS_LOG_DEFAULT;
        // The system-only initializer refuses standalone construction. Supply
        // the few properties read by handleNewFlow without starting a provider.
        FixtureProvider *guard = class_createInstance(FixtureProvider.class, 0);
        guard.config = [NEFilterProviderConfiguration new];
        guard.config.vendorConfiguration = @{@"blockThunderIP": @YES, @"blockThunderBT": @NO};
        guard.sessions = [NSMutableDictionary new];
        guard.processPath = @"/Applications/Thunder.app/Contents/XPCServices/DownloadService.xpc/Contents/MacOS/DownloadService";
        assert(settingsForSockets().rules.count == 2);
        assert(settingsForSockets().defaultAction == NEFilterActionFilterData);
        NEFilterNewFlowVerdict *inspectBoth = [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:1
                                                                                       filterOutbound:YES peekOutboundBytes:1];
        NEFilterSocketFlow *direct = flow(@"192.0.2.15", @"1500", nil);
        same([guard handleNewFlow:direct], inspectBoth);
        same(step(guard, direct, NO, 0, ascii(@"opaque payload")), [NEFilterDataVerdict dropVerdict]);
        ((FakeSocket *)direct).direction = NETrafficDirectionInbound;
        same([guard handleNewFlow:direct], inspectBoth);
        same(step(guard, direct, YES, 0, ascii(@"opaque payload")), [NEFilterDataVerdict dropVerdict]);
        NEFilterSocketFlow *cloud = flow(@"192.0.2.17", @"443", @"vod3429-aliyun04-vip-lixian.xunlei.com");
        same([guard handleNewFlow:cloud], [NEFilterNewFlowVerdict allowVerdict]);
        cloud = flow(nil, nil, nil);
        same([guard handleNewFlow:cloud], inspectBoth); // Address arrives with the first payload.
        struct sockaddr_in modern = {.sin_len = sizeof modern, .sin_family = AF_INET, .sin_port = htons(80)};
        assert(inet_pton(AF_INET, "192.0.2.17", &modern.sin_addr) == 1);
        ((FakeSocket *)cloud).remoteFlowEndpoint = nw_endpoint_create_address((const struct sockaddr *)&modern);
        same(step(guard, cloud, NO, 0, ascii(@"POST /login HTTP/1.1\r\nHost: login.xunlei.com\r\n\r\n")), [NEFilterDataVerdict allowVerdict]);
        same(step(guard, cloud, YES, 0, ascii(@"HTTP response")), [NEFilterDataVerdict allowVerdict]);
        NEFilterSocketFlow *fragmentedWeb = flow(@"192.0.2.17", @"80", nil);
        same([guard handleNewFlow:fragmentedWeb], inspectBoth);
        NSData *post = ascii(@"POST /login HTTP/1.1\r\nHost: login.xunlei.com\r\n\r\n");
        NEFilterDataVerdict *prefix = step(guard, fragmentedWeb, NO, 0, [post subdataWithRange:NSMakeRange(0, 6)]);
        assert(prefix && ![prefix.description isEqualToString:[NEFilterDataVerdict dropVerdict].description]);
        same(step(guard, fragmentedWeb, NO, 6, [post subdataWithRange:NSMakeRange(6, post.length - 6)]),
             [NEFilterDataVerdict allowVerdict]);
        NEFilterSocketFlow *unnamed443 = flow(@"192.0.2.17", @"443", nil);
        [guard handleNewFlow:unnamed443];
        same(step(guard, unnamed443, NO, 0, ascii(@"opaque payload")), [NEFilterDataVerdict dropVerdict]);
        NEFilterSocketFlow *unknown = flow(nil, nil, nil);
        same([guard handleNewFlow:unknown], inspectBoth);
        same(step(guard, unknown, NO, 0, ascii(@"opaque payload")), [NEFilterDataVerdict dropVerdict]);
        NEFilterSocketFlow *discovery = flow(nil, nil, nil);
        ((FakeSocket *)discovery).socketProtocol = IPPROTO_UDP;
        ((FakeSocket *)discovery).socketType = SOCK_DGRAM;
        same([guard handleNewFlow:discovery], inspectBoth);
        NSData *ping = ascii(@"d1:ad2:id20:abcdefghijklmnopqrste1:q4:ping1:t2:aa1:y1:qe");
        NSData *pong = ascii(@"d1:rd2:id20:abcdefghijklmnopqrste1:t2:aa1:y1:re");
        same(step(guard, discovery, NO, 0, ping), pass(ping.length));
        same(step(guard, discovery, YES, 0, pong), pass(pong.length));
        same(step(guard, discovery, YES, pong.length, pong), [NEFilterDataVerdict dropVerdict]); // Reply cannot be replayed.
        for (NSNumber *incoming in @[@NO, @YES]) {
            NEFilterSocketFlow *peer = flow(@"127.0.0.1", @"443", nil); // The web port must not bypass BT.
            same([guard handleNewFlow:peer], inspectBoth);
            unsigned char helloBytes[68] = "\023BitTorrent protocol";
            helloBytes[25] = 0x10;
            NSData *hello = [NSData dataWithBytes:helloBytes length:sizeof helloBytes];
            NSRange first = NSMakeRange(0, 1);
            NEFilterDataVerdict *waitHello = [NEFilterDataVerdict dataVerdictWithPassBytes:0 peekBytes:68];
            same(step(guard, peer, NO, 0, [hello subdataWithRange:first]), waitHello);
            same(step(guard, peer, NO, 1, [hello subdataWithRange:NSMakeRange(1, 67)]), pass(68));
            same(step(guard, peer, YES, 0, [hello subdataWithRange:first]), waitHello);
            same(step(guard, peer, YES, 0, hello), pass(68)); // The OS may repeat the peeked prefix.
            NSData *local = extended(0, @"d1:md11:ut_metadatai5eee");
            NSData *remote = extended(0, @"d1:md11:ut_metadatai7ee13:metadata_sizei3ee");
            same(step(guard, peer, NO, 68, local), pass(local.length));
            same(step(guard, peer, YES, 68, remote), pass(remote.length));
            NSData *query = extended(7, @"d8:msg_typei0e5:piecei0ee");
            NSData *reply = extended(5, @"d8:msg_typei1e5:piecei0e10:total_sizei3eeabc");
            same(step(guard, peer, NO, 68 + local.length, query), pass(query.length));
            NSUInteger replyStart = 68 + remote.length;
            (void)step(guard, peer, YES, replyStart, [reply subdataWithRange:NSMakeRange(0, 3)]);
            same(step(guard, peer, YES, replyStart + 3, [reply subdataWithRange:NSMakeRange(3, reply.length - 3)]),
                 pass(reply.length));
            unsigned char bytes[] = { 7, 0,0,0,0, 0,0,0,0, 'f' };
            NSData *piece = frame([NSData dataWithBytes:bytes length:sizeof bytes]);
            const BOOL rx = incoming.boolValue;
            same(step(guard, peer, rx, rx ? 68 + remote.length + reply.length : 68 + local.length + query.length, piece),
                 [NEFilterDataVerdict dropVerdict]);
        }
        guard.processPath = nil;
        same([guard handleNewFlow:direct], [NEFilterNewFlowVerdict allowVerdict]);
    }
}
