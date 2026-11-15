#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>
#import <Network/Network.h>
#import <Security/Security.h>
#import <os/log.h>
#import <bsm/libbsm.h>
#import <libproc.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <netdb.h>
#import "EndpointPolicy.h"
#import "PeerClassifier.h"
#import "PeekWindow.h"
#import "../../Integration/ThunderPeerWire.h"

static os_log_t auditLog;
static NSString *const appPrefix = @"/Thunder.app/Contents/";
static NSString *const thunderID = @"com.xunlei.Thunder";
static NSString *const guardPrefix = @"org.thunderguard.firewall.";
typedef NS_ENUM(NSUInteger, PGMode) { PGModeEndpoint, PGModeWeb, PGModePeer, PGModeDHT, PGModeBT, PGModeDone };

@interface PGSession : NSObject {
@public PGStream streams[2];
@public TGPeerSession metadata;
@public TGDHTRequest dht[8];
@public NSUInteger datagramOffsets[2];
@public NSUInteger nextDHT;
@public PGPeekWindow *windows[2];
}
@property (copy) NSString *path;
@property (copy) NSString *appID;
@property NSTimeInterval touched;
@property PGMode mode;
@property BOOL broadBT;
@property BOOL preserveByAddress;
@end
@implementation PGSession
- (instancetype)init {
    if ((self = [super init])) {
        windows[0] = [PGPeekWindow new];
        windows[1] = [PGPeekWindow new];
    }
    return self;
}
@end

@interface PGFilterProvider : NEFilterDataProvider
@property NSMutableDictionary<NSUUID *, PGSession *> *sessions;
@property NSCache<NSData *, NSString *> *paths;
@property NSCache<NSData *, NSString *> *identities;
@property NSCache<NSString *, NSDictionary *> *dns;
@property dispatch_semaphore_t dnsSlots;
@property NSTimeInterval nextReap;
@property NSTimeInterval evidenceWindow;
@property NSUInteger evidenceCount;
@end

static NSArray<NSString *> *knownCDNs(void) {
    return @[@"vod3429-aliyun04-vip-lixian.xunlei.com", @"vod3459-aliyun04-vip-lixian.xunlei.com",
             @"xfile2.a.88cdn.com"];
}

static NSString *normalizedAddress(NSString *raw) {
    NSString *host = [[raw componentsSeparatedByString:@"%"] firstObject];
    if (!host.length) return nil;
    struct in_addr v4;
    struct in6_addr v6;
    char buf[INET6_ADDRSTRLEN];
    if (inet_pton(AF_INET, host.UTF8String, &v4) == 1) return inet_ntop(AF_INET, &v4, buf, sizeof buf) ? @(buf) : nil;
    if (inet_pton(AF_INET6, host.UTF8String, &v6) != 1) return nil;
    if (IN6_IS_ADDR_V4MAPPED(&v6)) return inet_ntop(AF_INET, &v6.s6_addr[12], buf, sizeof buf) ? @(buf) : nil;
    return inet_ntop(AF_INET6, &v6, buf, sizeof buf) ? @(buf) : nil;
}

static void endpointFor(NEFilterSocketFlow *flow, NSString **host, NSString **port) {
    *host = nil;
    *port = nil;
    if (@available(macOS 15.0, *)) {
        nw_endpoint_t modern = flow.remoteFlowEndpoint;
        if (modern) {
            nw_endpoint_type_t type = nw_endpoint_get_type(modern);
            if (type == nw_endpoint_type_address) {
                const struct sockaddr *address = nw_endpoint_get_address(modern);
                char numeric[NI_MAXHOST];
                if (address && !getnameinfo(address, address->sa_len, numeric, sizeof numeric, NULL, 0, NI_NUMERICHOST))
                    *host = @(numeric);
            } else if (type == nw_endpoint_type_host) {
                const char *name = nw_endpoint_get_hostname(modern);
                if (name) *host = @(name);
            }
            if (*host) {
                uint16_t number = nw_endpoint_get_port(modern);
                if (number) *port = [@(number) stringValue];
                return;
            }
        }
    }
    NWEndpoint *endpoint = flow.remoteEndpoint;
    if ([endpoint isKindOfClass:NWHostEndpoint.class]) {
        *host = [(NWHostEndpoint *)endpoint hostname];
        *port = [(NWHostEndpoint *)endpoint port];
    }
}

static NEFilterSettings *settingsForSockets(void) {
    NSMutableArray<NEFilterRule *> *rules = [NSMutableArray new];
    // A wildcard rule explicitly excludes loopback. Ask for it separately, for
    // both directions, and still let the provider decide what to do.
    for (NSString *address in @[@"127.0.0.1", @"::1"]) {
        NWHostEndpoint *loopback = [NWHostEndpoint endpointWithHostname:address port:@"0"];
        NENetworkRule *rule = [[NENetworkRule alloc] initWithRemoteNetwork:loopback
            remotePrefix:[address isEqualToString:@"::1"] ? 128 : 8 localNetwork:nil localPrefix:0
            protocol:NENetworkRuleProtocolAny direction:NETrafficDirectionAny];
        [rules addObject:[[NEFilterRule alloc] initWithNetworkRule:rule action:NEFilterActionFilterData]];
    }
    return [[NEFilterSettings alloc] initWithRules:rules defaultAction:NEFilterActionFilterData];
}

@implementation PGFilterProvider
- (void)startFilterWithCompletionHandler:(void (^)(NSError *))done {
    self.sessions = [NSMutableDictionary new];
    self.paths = [NSCache new];
    self.paths.countLimit = 2048;
    self.identities = [NSCache new];
    self.identities.countLimit = 4096;
    self.dns = [NSCache new];
    self.dns.countLimit = 128;
    self.dnsSlots = dispatch_semaphore_create(3);
    [self applySettings:settingsForSockets()
       completionHandler:^(NSError *error) {
        if (error) os_log_error(auditLog, "P2PGUARD_START_ERROR %{public}@", error.localizedDescription);
        else {
            NSDictionary *policy = self.filterConfiguration.vendorConfiguration;
            os_log(auditLog, "P2PGUARD_READY ip=%d bt=%d global=%d",
                   [policy[@"blockThunderIP"] isEqual:@YES], [policy[@"blockThunderBT"] isEqual:@YES],
                   [policy[@"blockAllBT"] isEqual:@YES]);
        }
        done(error);
        if (!error) dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            for (NSString *name in knownCDNs()) [self addressesForName:name];
        });
    }];
}

- (void)stopFilterWithReason:(NEProviderStopReason)reason completionHandler:(void (^)(void))done { done(); }

- (NSString *)applicationID:(NSData *)token {
    if (token.length != sizeof(audit_token_t)) return nil;
    NSString *cached = [self.identities objectForKey:token];
    if (cached) return cached.length ? cached : nil;
    audit_token_t audit;
    [token getBytes:&audit length:sizeof audit];
    if (audit_token_to_pid(audit) <= 0) return nil;
    SecTaskRef task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, audit);
    NSString *identifier = task ? CFBridgingRelease(SecTaskCopySigningIdentifier(task, NULL)) : nil;
    if (task) CFRelease(task);
    [self.identities setObject:identifier ?: @"" forKey:token];
    return identifier;
}

- (NSString *)processName:(NSData *)token {
    if (token.length != sizeof(audit_token_t)) return nil;
    audit_token_t audit;
    [token getBytes:&audit length:sizeof audit];
    pid_t pid = audit_token_to_pid(audit);
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (pid > 0 && proc_pidpath(pid, path, sizeof path) > 0) return [@(path) lastPathComponent];
    return nil;
}

- (NSString *)thunderPath:(NSData *)token {
    if (token.length != sizeof(audit_token_t)) return nil;
    NSString *cached = [self.paths objectForKey:token];
    if (cached) return cached.length ? cached : nil;
    audit_token_t audit;
    [token getBytes:&audit length:sizeof audit];
    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    pid_t pid = audit_token_to_pid(audit);
    if (pid <= 0) return nil;
    NSString *p = proc_pidpath(pid, path, sizeof path) > 0 ? @(path) : nil;
    if (![p containsString:appPrefix] &&
        ![p isEqualToString:@"/Library/PrivilegedHelperTools/com.xunlei.Thunder.HelperTool"]) {
        // Resolve an audited caller even when the content-filter sandbox can't
        // read its executable path. Require Xunlei's signing team as well as ID.
        SecTaskRef task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, audit);
        NSString *identifier = task ? CFBridgingRelease(SecTaskCopySigningIdentifier(task, NULL)) : nil;
        if (task) CFRelease(task);
        NSDictionary *known = @{
            @"com.xunlei.Thunder": @"Thunder",
            @"com.xunlei.DownloadService": @"DownloadService",
            @"com.xunlei.Thunder.ThunderHelper": @"ThunderHelper",
            @"com.xunlei.Thunder.HelperTool": @"ThunderHelper",
            @"com.xunlei.XLEmbeddedPlayer": @"XLEmbeddedPlayer",
        };
        NSString *name = identifier ? known[identifier] : nil;
        p = @"";
        if (name) {
            SecCodeRef guest = NULL;
            SecRequirementRef requirement = NULL;
            OSStatus status = SecCodeCopyGuestWithAttributes(NULL,
                (__bridge CFDictionaryRef)@{(__bridge NSString *)kSecGuestAttributeAudit: token}, kSecCSDefaultFlags, &guest);
            if (status == errSecSuccess && SecRequirementCreateWithString(
                    CFSTR("anchor apple generic and certificate leaf[subject.OU] = SXKSDVK696"),
                    kSecCSDefaultFlags, &requirement) == errSecSuccess &&
                SecCodeCheckValidity(guest, kSecCSDefaultFlags, requirement) == errSecSuccess) p = name;
            if (requirement) CFRelease(requirement);
            if (guest) CFRelease(guest);
        }
    }
    [self.paths setObject:p forKey:token];
    return p.length ? p : nil;
}

- (NSSet<NSString *> *)addressesForName:(NSString *)host {
    if (!host.length) return nil;
    NSString *key = host.lowercaseString;
    NSDictionary *entry = [self.dns objectForKey:key];
    if ([entry[@"until"] doubleValue] > NSProcessInfo.processInfo.systemUptime) return entry[@"addresses"];
    if (dispatch_semaphore_wait(self.dnsSlots, DISPATCH_TIME_NOW)) return nil;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block NSSet<NSString *> *result;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
        struct addrinfo *addresses = NULL;
        NSMutableSet<NSString *> *matches = [NSMutableSet set];
        if (getaddrinfo(key.UTF8String, NULL, &hints, &addresses) == 0) {
            for (const struct addrinfo *row = addresses; row; row = row->ai_next) {
                char numeric[NI_MAXHOST];
                if (getnameinfo(row->ai_addr, row->ai_addrlen, numeric, sizeof numeric, NULL, 0, NI_NUMERICHOST) == 0) {
                    NSString *address = normalizedAddress(@(numeric));
                    if (address) [matches addObject:address];
                }
            }
            freeaddrinfo(addresses);
        }
        result = [matches copy];
        [self.dns setObject:@{@"addresses": result, @"until": @(NSProcessInfo.processInfo.systemUptime + (result.count ? 60 : 5))}
                      forKey:key];
        dispatch_semaphore_signal(self.dnsSlots);
        dispatch_semaphore_signal(done);
    });
    if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 350 * NSEC_PER_MSEC))) return nil;
    return result;
}

- (NEFilterNewFlowVerdict *)handleNewFlow:(NEFilterFlow *)flow {
    if (![flow isKindOfClass:NEFilterSocketFlow.class]) return [NEFilterNewFlowVerdict allowVerdict];
    NSDictionary *policy = self.filterConfiguration.vendorConfiguration;
    BOOL legacyBT = [policy[@"blockThunderBT"] isEqual:@YES];
    BOOL legacyIP = [policy[@"blockThunderIP"] isEqual:@YES];
    BOOL globalBT = [policy[@"blockAllBT"] isEqual:@YES];
    NSDictionary *overrides = [policy[@"appBTOverrides"] isKindOfClass:NSDictionary.class] ? policy[@"appBTOverrides"] : nil;
    if (!legacyBT && !legacyIP && !globalBT && !overrides.count) return [NEFilterNewFlowVerdict allowVerdict];
    NEFilterSocketFlow *socket = (NEFilterSocketFlow *)flow;
    BOOL tcp = socket.socketProtocol == IPPROTO_TCP && socket.socketType == SOCK_STREAM;
    BOOL udp = socket.socketProtocol == IPPROTO_UDP && socket.socketType == SOCK_DGRAM;
    if (!tcp && !udp) return [NEFilterNewFlowVerdict allowVerdict];
    NSString *p = [self thunderPath:flow.sourceProcessAuditToken] ?: [self thunderPath:flow.sourceAppAuditToken];
    NSString *app = p ? thunderID : ([self applicationID:flow.sourceAppAuditToken] ?: [self applicationID:flow.sourceProcessAuditToken]);
    if ([app hasPrefix:guardPrefix]) return [NEFilterNewFlowVerdict allowVerdict];
    NSString *override = app ? overrides[app] : nil;
    BOOL blockBT = [override isEqual:@"block"] || (![override isEqual:@"allow"] && (globalBT || (p && legacyBT)));
    BOOL blockIP = p != nil && legacyIP;
    if (!blockIP && (!blockBT || !tcp)) return [NEFilterNewFlowVerdict allowVerdict];
    NSString *host, *port;
    endpointFor(socket, &host, &port);
    // Prefer system-supplied names. The endpoint's numerical address alone
    // does not distinguish a raw peer from URLSession or curl's resolved CDN.
    BOOL named = blockIP && [self hasName:socket endpoint:host];
    p = p ?: [self processName:flow.sourceProcessAuditToken] ?: app ?: @"未知进程";
    [self noteObservation:p host:host named:[self hasName:socket endpoint:host] tcp:tcp blockIP:blockIP blockBT:blockBT];
    BOOL inspectIP = blockIP && !named;
    if (!inspectIP && (!blockBT || !tcp)) return [NEFilterNewFlowVerdict allowVerdict];
    PGSession *session = [PGSession new];
    session.path = p;
    session.appID = app;
    session.preserveByAddress = inspectIP;
    session.broadBT = blockBT;
    session.mode = inspectIP ? [self modeFor:socket host:host port:port] : PGModeBT;
    session.touched = NSProcessInfo.processInfo.systemUptime;
    @synchronized (self.sessions) {
        if (session.touched >= self.nextReap) {
            self.nextReap = session.touched + 30;
            for (NSUUID *key in self.sessions.allKeys) {
                PGSession *existing = self.sessions[key];
                if (existing.preserveByAddress && session.touched - existing.touched > 300)
                    [self.sessions removeObjectForKey:key];
            }
        }
        if (!inspectIP && self.sessions.count >= 4096) return [NEFilterNewFlowVerdict allowVerdict];
        if (self.sessions.count >= 8192) {
            if (!inspectIP) return [NEFilterNewFlowVerdict allowVerdict];
            [self logFlow:flow session:session direction:@"connection" reason:@"inspection-capacity"];
            return [NEFilterNewFlowVerdict dropVerdict];
        }
        self.sessions[flow.identifier] = session;
    }
    NEFilterNewFlowVerdict *verdict = [NEFilterNewFlowVerdict filterDataVerdictWithFilterInbound:YES peekInboundBytes:1
                                                                                filterOutbound:YES peekOutboundBytes:1];
    // Generic inspection tracks ordinary sockets until the flow closes;
    // reaping an idle socket can disrupt an unrelated, still-live protocol.
    if (!inspectIP) verdict.shouldReport = YES;
    return verdict;
}

- (void)handleReport:(NEFilterReport *)report {
    if (report.event == NEFilterReportEventFlowClosed && report.flow.identifier) {
        @synchronized (self.sessions) { [self.sessions removeObjectForKey:report.flow.identifier]; }
    }
}

- (BOOL)hasName:(NEFilterSocketFlow *)flow endpoint:(NSString *)host {
    return pg_dns_name(flow.remoteHostname.UTF8String) || pg_dns_name(flow.URL.host.UTF8String) ||
           pg_dns_name(host.UTF8String);
}

- (PGMode)modeFor:(NEFilterSocketFlow *)flow host:(NSString *)host port:(NSString *)port {
    if (!host.length || !port.length) return PGModeEndpoint;
    if (flow.socketProtocol == IPPROTO_UDP) return PGModeDHT;
    if (flow.direction == NETrafficDirectionOutbound &&
        ([port isEqualToString:@"80"] || [port isEqualToString:@"443"])) return PGModeWeb;
    return PGModePeer;
}

- (void)noteObservation:(NSString *)path host:(NSString *)host named:(BOOL)named tcp:(BOOL)tcp
                blockIP:(BOOL)blockIP blockBT:(BOOL)blockBT {
    if (![self takeEvidenceSlot]) return;
    // No destination, URL or payload in routine diagnostics.
    os_log(auditLog, "P2PGUARD_FLOW build=17 process=%{public}@ endpoint=%{public}s transport=%{public}s ip=%d bt=%d",
           path.lastPathComponent, named ? "named" : host.length ? "address" : "pending",
           tcp ? "tcp" : "udp", blockIP, blockBT);
}

- (BOOL)takeEvidenceSlot {
    @synchronized (self) {
        NSTimeInterval now = NSProcessInfo.processInfo.systemUptime;
        if (now >= self.evidenceWindow) { self.evidenceWindow = now + 15; self.evidenceCount = 0; }
        if (self.evidenceCount >= 32) return NO;
        ++self.evidenceCount;
        return YES;
    }
}

- (void)logFlow:(NEFilterFlow *)flow session:(PGSession *)session direction:(NSString *)direction reason:(NSString *)reason {
    [self logFlow:flow session:session direction:direction reason:reason detail:nil];
}

- (void)logFlow:(NEFilterFlow *)flow session:(PGSession *)session direction:(NSString *)direction
         reason:(NSString *)reason detail:(NSString *)detail {
    NSString *host, *port;
    endpointFor((NEFilterSocketFlow *)flow, &host, &port);
    NSDictionary *event = @{@"app": session.appID ?: @"", @"process": session.path.lastPathComponent,
        @"address": host ?: @"", @"port": port ?: @"",
        @"direction": direction, @"reason": reason, @"detail": detail ?: @"", @"timestamp": @(NSDate.date.timeIntervalSince1970)};
    NSData *data = [NSJSONSerialization dataWithJSONObject:event options:0 error:NULL];
    if (data) os_log(auditLog, "P2PGUARD_BLOCK %{public}@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
}

- (NEFilterDataVerdict *)inspectAddress:(NEFilterSocketFlow *)flow session:(PGSession *)session data:(NSData *)data final:(BOOL)final {
    NSString *hostName, *portString;
    endpointFor(flow, &hostName, &portString);
    unsigned port = (unsigned)portString.intValue;
    char host[254];
    PGNameResult name = pg_web_name(port, data.bytes, data.length, host);
    if (name.action == PGNameWait && !final) return [NEFilterDataVerdict dataVerdictWithPassBytes:0 peekBytes:name.required];
    NSString *ip = normalizedAddress(hostName);
    BOOL named = NO;
    if (name.action == PGNameFound) {
        // Keep known service names working during CDN DNS rotation. The
        // client still performs its normal certificate validation.
        named = pg_xunlei_service(host) || (ip && [[self addressesForName:@(host)] containsObject:ip]);
    } else if (port == 443 && ip && data.length && ((const uint8_t *)data.bytes)[0] == 22) {
        // For TLS without SNI, only reuse DNS evidence for known CDN names.
        NSDictionary *entry;
        for (NSString *cdn in knownCDNs()) {
            entry = [self.dns objectForKey:cdn];
            if ([entry[@"until"] doubleValue] > NSProcessInfo.processInfo.systemUptime && [entry[@"addresses"] containsObject:ip]) {
                named = YES;
                break;
            }
        }
    }
    session.mode = PGModeDone;
    if (named) return [NEFilterDataVerdict allowVerdict];
    [self logFlow:flow session:session direction:@"connection" reason:@"direct-ip"];
    return [NEFilterDataVerdict dropVerdict];
}

- (NEFilterDataVerdict *)inspectPeer:(NEFilterSocketFlow *)flow session:(PGSession *)session
                            inbound:(BOOL)incoming offset:(NSUInteger)offset data:(NSData *)data {
    if (session.mode == PGModeDHT) {
        BOOL allowed = NO;
        if (offset == session->datagramOffsets[incoming] && data.length <= NSUIntegerMax - offset) {
            TGDHTRequest request = {0};
            if (incoming) {
                for (unsigned i = 0; i < 8; ++i) {
                    if (tg_dht_reply(data.bytes, data.length, &session->dht[i])) {
                        session->dht[i].length = 0;
                        allowed = YES;
                        break;
                    }
                }
            } else if (tg_dht_query(data.bytes, data.length, &request)) {
                session->dht[session->nextDHT++ % 8] = request;
                allowed = YES;
            }
        }
        if (allowed) {
            session->datagramOffsets[incoming] += data.length;
            return [NEFilterDataVerdict dataVerdictWithPassBytes:data.length peekBytes:1];
        }
    } else {
        PGPeekWindow *window = session->windows[incoming];
        if (![window receive:data at:offset limit:2 * TG_MAX_FRAME]) {
            [self logFlow:flow session:session direction:@"connection" reason:@"inspection-offset" detail:@"Incomplete stream"];
            return [NEFilterDataVerdict dropVerdict];
        }
        const NSUInteger previous = window.base;
        while (window.bytes.length) {
            const uint8_t *bytes = window.bytes.bytes;
            TGDecision decision = tg_peer_data(&session->metadata, incoming, window.base, bytes, window.bytes.length);
            if (decision.action == TGWait)
                return [NEFilterDataVerdict dataVerdictWithPassBytes:window.base - previous peekBytes:decision.count];
            if (decision.action == TGPass) {
                if (window.base && decision.count > 6 && bytes[4] == 20 && bytes[5] != 0 && [self takeEvidenceSlot])
                    os_log(auditLog, "P2PGUARD_METADATA process=%{public}@ direction=%{public}s",
                           session.path.lastPathComponent, incoming ? "inbound" : "outbound");
                [window consume:decision.count];
                continue;
            }
            if (decision.action == TGDropFile) {
                BOOL upload = bytes[4] == 7 ? !incoming : incoming;
                NSString *detail = bytes[4] == 7 ? @"piece" : bytes[4] == 6 ? @"request" : @"cancel";
                if (bytes[4] != 8) {
                    [self logFlow:flow session:session direction:upload ? @"upload" : @"download"
                           reason:@"bt-file" detail:detail];
                } else {
                    [self logFlow:flow session:session direction:@"connection" reason:@"bt-control" detail:detail];
                }
                return [NEFilterDataVerdict dropVerdict];
            }
            [self logFlow:flow session:session direction:@"connection" reason:@"direct-ip"
                   detail:window.base ? @"other-peer-message" : @"unrecognized-handshake"];
            return [NEFilterDataVerdict dropVerdict];
        }
        return [NEFilterDataVerdict dataVerdictWithPassBytes:window.base - previous peekBytes:1];
    }
    [self logFlow:flow session:session direction:@"connection" reason:@"direct-ip"];
    return [NEFilterDataVerdict dropVerdict];
}

- (NEFilterDataVerdict *)inspectStandardBT:(NEFilterFlow *)flow session:(PGSession *)session
                                 inbound:(BOOL)incoming offset:(NSUInteger)offset data:(NSData *)data {
    PGPeekWindow *window = session->windows[incoming];
    PGStream *stream = &session->streams[incoming];
    if (![window receive:data at:offset limit:2 * (1024 * 1024 + 4)]) {
        if (!stream->identified) {
            session.mode = PGModeDone;
            return [NEFilterDataVerdict allowVerdict];
        }
        [self logFlow:flow session:session direction:@"connection" reason:@"inspection-offset"];
        return [NEFilterDataVerdict dropVerdict];
    }
    const NSUInteger before = window.base;
    while (window.bytes.length) {
        const uint8_t *bytes = window.bytes.bytes;
        PGDecision decision = pg_classify(stream, incoming, window.base, bytes, window.bytes.length);
        switch (decision.action) {
            case PGPeek:
                return [NEFilterDataVerdict dataVerdictWithPassBytes:window.base - before peekBytes:decision.count];
            case PGPass:
                [window consume:decision.count];
                break;
            case PGUnidentified:
                if (!stream->identified) {
                    session.mode = PGModeDone;
                    return [NEFilterDataVerdict allowVerdict];
                }
                [self logFlow:flow session:session direction:@"connection" reason:@"bt-control" detail:@"invalid-frame"];
                return [NEFilterDataVerdict dropVerdict];
            default:
                // Release preceding complete metadata before dropping a file
                // request or piece that arrived in the same read callback.
                if (window.base > before)
                    return [NEFilterDataVerdict dataVerdictWithPassBytes:window.base - before peekBytes:5];
                [self logFlow:flow session:session direction:decision.action == PGBlockUpload ? @"upload" : @"download"
                       reason:@"bt-file" detail:bytes[4] == 7 ? @"piece" : @"request"];
                return [NEFilterDataVerdict dropVerdict];
        }
    }
    return [NEFilterDataVerdict dataVerdictWithPassBytes:window.base - before peekBytes:stream->identified ? 4 : 1];
}

- (NEFilterDataVerdict *)inspect:(NEFilterFlow *)flow inbound:(BOOL)incoming offset:(NSUInteger)offset data:(NSData *)data {
    PGSession *session;
    @synchronized (self.sessions) {
        session = self.sessions[flow.identifier];
        session.touched = NSProcessInfo.processInfo.systemUptime;
    }
    if (!session) {
        // Only flows we asked to peek call this. Evicted sessions must not let
        // their original pending bytes through without a decision.
        return [NEFilterDataVerdict dropVerdict];
    }
    NEFilterSocketFlow *socket = (NEFilterSocketFlow *)flow;
    @synchronized (session) {
        if (session.mode == PGModeEndpoint) {
            NSString *host, *port;
            endpointFor(socket, &host, &port);
            if ([self hasName:socket endpoint:host]) {
                session.mode = session.broadBT && socket.socketProtocol == IPPROTO_TCP ? PGModeBT : PGModeDone;
            } else {
                session.mode = [self modeFor:socket host:host port:port];
                if (session.mode == PGModeEndpoint)
                    session.mode = socket.socketProtocol == IPPROTO_UDP ? PGModeDHT : PGModePeer;
            }
        }
        if (session.mode == PGModeWeb) {
            PGPeekWindow *window = session->windows[incoming];
            if (![window receive:data at:offset limit:2 * TG_MAX_FRAME]) {
                [self logFlow:flow session:session direction:@"connection" reason:@"inspection-offset" detail:@"Incomplete web prefix"];
                return [NEFilterDataVerdict dropVerdict];
            }
            const uint8_t *bytes = window.bytes.bytes;
            // Peers can listen on web ports. Inspect both directions so a
            // handshake or file piece from the server can't bypass the check.
            if (window.bytes.length && bytes[0] == 19) session.mode = PGModePeer;
            else if (!incoming) return [self inspectAddress:socket session:session data:window.bytes final:NO];
            else {
                [self logFlow:flow session:session direction:@"connection" reason:@"direct-ip"];
                return [NEFilterDataVerdict dropVerdict];
            }
        }
        if (session.mode == PGModePeer || session.mode == PGModeDHT)
            return [self inspectPeer:socket session:session inbound:incoming offset:offset data:data];
        if (session.mode == PGModeBT)
            return [self inspectStandardBT:flow session:session inbound:incoming offset:offset data:data];
        return [NEFilterDataVerdict allowVerdict];
    }
}
- (NEFilterDataVerdict *)handleInboundDataFromFlow:(NEFilterFlow *)flow readBytesStartOffset:(NSUInteger)offset readBytes:(NSData *)data {
    return [self inspect:flow inbound:YES offset:offset data:data];
}
- (NEFilterDataVerdict *)handleOutboundDataFromFlow:(NEFilterFlow *)flow readBytesStartOffset:(NSUInteger)offset readBytes:(NSData *)data {
    return [self inspect:flow inbound:NO offset:offset data:data];
}
- (NEFilterDataVerdict *)complete:(NEFilterFlow *)flow inbound:(BOOL)inbound {
    PGSession *session;
    @synchronized (self.sessions) { session = self.sessions[flow.identifier]; }
    if (!session) return [NEFilterDataVerdict dropVerdict];
    @synchronized (session) {
        if (session.mode == PGModeWeb && !inbound)
            return [self inspectAddress:(NEFilterSocketFlow *)flow session:session data:NSData.data final:YES];
        if (session.preserveByAddress && session.mode != PGModeDone && session.mode != PGModeBT)
            return [NEFilterDataVerdict dropVerdict]; // Do not release any incomplete frame on EOF.
    }
    return [NEFilterDataVerdict allowVerdict];
}
- (NEFilterDataVerdict *)handleInboundDataCompleteForFlow:(NEFilterFlow *)flow { return [self complete:flow inbound:YES]; }
- (NEFilterDataVerdict *)handleOutboundDataCompleteForFlow:(NEFilterFlow *)flow { return [self complete:flow inbound:NO]; }
@end

int main(void) {
    @autoreleasepool {
        auditLog = os_log_create("org.thunderguard.firewall", "packet-evidence");
        [NEProvider startSystemExtensionMode];
    }
    dispatch_main();
}
