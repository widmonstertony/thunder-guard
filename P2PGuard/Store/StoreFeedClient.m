#import "StoreFeedClient.h"
#import "StoreFeedProtocol.h"

@interface PGStoreFeedRequest : NSObject
@property NSXPCConnection *connection;
@property (copy) void (^completion)(NSData *);
- (void)finish:(NSData *)data;
@end

@implementation PGStoreFeedRequest
- (void)finish:(NSData *)data {
    NSXPCConnection *connection;
    void (^completion)(NSData *);
    @synchronized (self) {
        completion = _completion;
        if (!completion) return;
        _completion = nil;
        connection = _connection;
        _connection = nil;
    }
    connection.invalidationHandler = nil;
    [connection invalidate];
    completion(data);
}
@end

void PGReadStoreFeed(NSString *service, NSString *requirement, void (^completion)(NSData *)) {
    PGStoreFeedRequest *request = [PGStoreFeedRequest new];
    request.completion = completion;
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:service options:NSXPCConnectionPrivileged];
    request.connection = connection;
    [connection setCodeSigningRequirement:requirement];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(PGStoreFeed)];
    connection.invalidationHandler = ^{ [request finish:nil]; };
    [connection resume];
    // Use the Objective-C protocol directly. A Swift existential cast on the
    // NSXPC forwarding object can trap on macOS before the service is present.
    id<PGStoreFeed> proxy = [connection remoteObjectProxyWithErrorHandler:^(NSError *error) { [request finish:nil]; }];
    if (!proxy) { [request finish:nil]; return; }
    [proxy getSnapshotWithReply:^(NSData *data) { [request finish:data]; }];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
                   ^{ [request finish:nil]; });
}
