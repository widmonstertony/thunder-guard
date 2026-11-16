#import <Foundation/Foundation.h>

@interface PGStoreFeedServer : NSObject
+ (instancetype)shared;
- (void)start;
- (void)reset;
- (void)recordFlow:(NSUUID *)flow forUser:(uid_t)user fields:(NSDictionary *)fields;
- (void)recordBlock:(NSDictionary *)event forUser:(uid_t)user;
@end
