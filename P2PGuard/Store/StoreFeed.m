#import "StoreFeed.h"
#import "StoreFeedProtocol.h"

typedef NS_ENUM(NSUInteger, PGBlockKind) { PGBlockUpload, PGBlockDownload, PGBlockOther };
static const NSUInteger PGBlockHistoryLimit = 500;
static const NSUInteger PGBlockSnapshotLimit = 250;
static const NSTimeInterval PGBlockLifetime = 600;

static PGBlockKind blockKind(NSDictionary *event) {
    if ([event[@"reason"] isEqual:@"bt-file"]) {
        if ([event[@"direction"] isEqual:@"upload"]) return PGBlockUpload;
        if ([event[@"direction"] isEqual:@"download"]) return PGBlockDownload;
    }
    return PGBlockOther;
}

@interface PGStoreFeedServer () <NSXPCListenerDelegate>
@property NSXPCListener *listener;
@property NSMutableDictionary<NSUUID *, NSDictionary *> *flows;
@property NSArray<NSMutableArray<NSDictionary *> *> *blocksByKind;
- (NSData *)snapshotForUser:(uid_t)user;
@end

@interface PGStoreFeedReader : NSObject <PGStoreFeed>
@property uid_t user;
@property (weak) PGStoreFeedServer *source;
@end

@implementation PGStoreFeedReader
- (void)getSnapshotWithReply:(void (^)(NSData *))reply {
    reply([self.source snapshotForUser:self.user] ?: NSData.data);
}
@end

@implementation PGStoreFeedServer
+ (instancetype)shared {
    static PGStoreFeedServer *server;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ server = [PGStoreFeedServer new]; [server reset]; });
    return server;
}
- (void)start {
    NSDictionary *info = NSBundle.mainBundle.infoDictionary;
    NSString *name = info[@"NetworkExtension"][@"NEMachServiceName"];
    NSString *team = info[@"PGSigningTeam"];
    NSString *client = info[@"PGClientIdentifier"];
    if (!name.length || !client.length || team.length != 10) return;
    self.listener = [[NSXPCListener alloc] initWithMachServiceName:name];
    NSString *requirement = [NSString stringWithFormat:
        @"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = %@", client, team];
    [self.listener setConnectionCodeSigningRequirement:requirement];
    self.listener.delegate = self;
    [self.listener resume];
}
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)connection {
    if (listener != self.listener || connection.effectiveUserIdentifier < 501 ||
        connection.effectiveUserIdentifier == (uid_t)-1) return NO;
    PGStoreFeedReader *reader = [PGStoreFeedReader new];
    reader.user = connection.effectiveUserIdentifier;
    reader.source = self;
    connection.exportedObject = reader;
    connection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(PGStoreFeed)];
    [connection resume];
    return YES;
}
- (void)reset {
    @synchronized (self) {
        self.flows = [NSMutableDictionary new];
        self.blocksByKind = @[[NSMutableArray new], [NSMutableArray new], [NSMutableArray new]];
    }
}
- (void)recordFlow:(NSUUID *)flow forUser:(uid_t)user fields:(NSDictionary *)fields {
    if (!flow || user < 501 || user == (uid_t)-1) return;
    @synchronized (self) {
        if (self.flows.count >= 1024 && !self.flows[flow]) {
            NSUUID *oldest;
            double oldestTime = INFINITY;
            for (NSUUID *key in self.flows) {
                double t = [self.flows[key][@"seen"] doubleValue];
                if (t < oldestTime) { oldestTime = t; oldest = key; }
            }
            if (oldest) [self.flows removeObjectForKey:oldest];
        }
        self.flows[flow] = @{@"uid": @(user), @"seen": @(NSProcessInfo.processInfo.systemUptime), @"row": fields};
    }
}
- (void)recordBlock:(NSDictionary *)event forUser:(uid_t)user {
    if (user < 501 || user == (uid_t)-1) return;
    @synchronized (self) {
        NSMutableArray *history = self.blocksByKind[blockKind(event)];
        [history addObject:@{@"uid": @(user), @"row": event}];
        if (history.count > PGBlockHistoryLimit) [history removeObjectAtIndex:0];
    }
}
- (NSData *)snapshotForUser:(uid_t)user {
    double recent = NSProcessInfo.processInfo.systemUptime - 18.0;
    double evidence = NSDate.date.timeIntervalSince1970 - PGBlockLifetime;
    NSMutableArray *flows = [NSMutableArray new];
    NSMutableArray *blocks = [NSMutableArray new];
    @synchronized (self) {
        for (NSUUID *key in self.flows.allKeys) {
            NSDictionary *entry = self.flows[key];
            if ([entry[@"seen"] doubleValue] < recent) [self.flows removeObjectForKey:key];
            else if ([entry[@"uid"] unsignedIntValue] == user) [flows addObject:entry[@"row"]];
        }
        // Keep the per-category limit on the feed too; a single limit here would
        // hide BT verdicts even though they are still in the provider's history.
        for (NSMutableArray *history in self.blocksByKind) {
            NSUInteger count = 0;
            for (NSDictionary *entry in history.reverseObjectEnumerator) {
                NSDictionary *event = entry[@"row"];
                if ([event[@"timestamp"] doubleValue] < evidence || [entry[@"uid"] unsignedIntValue] != user) continue;
                [blocks addObject:event];
                if (++count >= PGBlockSnapshotLimit) break;
            }
        }
    }
    [blocks sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"timestamp" ascending:NO]]];
    return [NSJSONSerialization dataWithJSONObject:@{@"flows": flows, @"blocks": blocks} options:0 error:NULL] ?: NSData.data;
}
@end
