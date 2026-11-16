#import <Foundation/Foundation.h>

@protocol PGStoreFeed
- (void)getSnapshotWithReply:(void (^)(NSData *))reply;
@end
