#import "../P2PGuard/Store/StoreFeed.h"
#include <assert.h>

@interface PGStoreFeedServer (TestSnapshot)
- (NSData *)snapshotForUser:(uid_t)user;
@end

static NSDictionary *event(NSString *reason, NSString *direction, NSString *port, double timestamp) {
    return @{@"app": @"test", @"process": @"Peer", @"address": @"127.0.0.1", @"port": port,
             @"reason": reason, @"direction": direction, @"detail": @"piece", @"timestamp": @(timestamp)};
}

static NSArray<NSDictionary *> *blocks(PGStoreFeedServer *server, uid_t user) {
    NSDictionary *snapshot = [NSJSONSerialization JSONObjectWithData:[server snapshotForUser:user] options:0 error:NULL];
    return snapshot[@"blocks"];
}

int main(void) {
    @autoreleasepool {
        PGStoreFeedServer *server = [PGStoreFeedServer new];
        [server reset];
        double now = NSDate.date.timeIntervalSince1970;
        NSDictionary *upload = event(@"bt-file", @"upload", @"50001", now - 585);
        NSDictionary *download = event(@"bt-file", @"download", @"50002", now - 584);
        [server recordBlock:upload forUser:501];
        [server recordBlock:download forUser:501];
        [server recordBlock:event(@"bt-file", @"upload", @"50003", now - 601) forUser:501];
        [server recordBlock:event(@"bt-file", @"download", @"50004", now - 601) forUser:501];
        NSDictionary *otherUser = event(@"bt-file", @"upload", @"50005", now - 583);
        [server recordBlock:otherUser forUser:502];

        // More recent IP denials than both the former feed and history limit.
        for (NSUInteger i = 0; i < 1000; ++i) {
            NSString *port = [@(51000 + i) stringValue];
            [server recordBlock:event(@"direct-ip", @"connection", port, now - 10 + i / 1000.0) forUser:501];
        }
        NSArray *retained = blocks(server, 501);
        assert(retained.count == 252);
        assert([retained[250] isEqual:download]);
        assert([retained[251] isEqual:upload]);
        assert([blocks(server, 502) isEqual:@[otherUser]]);

        // Upload pressure cannot replace downloads or the separate IP list.
        for (NSUInteger i = 0; i < 1000; ++i) {
            NSString *port = [@(52000 + i) stringValue];
            [server recordBlock:event(@"bt-file", @"upload", port, now - 1 + i / 1000.0) forUser:501];
        }
        retained = blocks(server, 501);
        assert(retained.count == 501);
        assert([retained.lastObject isEqual:download]);
        assert(![retained containsObject:upload]);
        assert([retained[250][@"reason"] isEqual:@"direct-ip"]);
    }
    return 0;
}
