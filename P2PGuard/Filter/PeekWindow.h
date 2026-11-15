#import <Foundation/Foundation.h>

// NetworkExtension can report the newly peeked suffix or repeat bytes from the
// last release offset. Reconcile both before classifying a split frame.
@interface PGPeekWindow : NSObject
@property (nonatomic, readonly) NSUInteger base;
@property (nonatomic, readonly) NSMutableData *bytes;
- (BOOL)receive:(NSData *)data at:(NSUInteger)offset limit:(NSUInteger)limit;
- (void)consume:(NSUInteger)count;
@end

@implementation PGPeekWindow
- (instancetype)init {
    if ((self = [super init])) _bytes = [NSMutableData new];
    return self;
}

- (BOOL)receive:(NSData *)data at:(NSUInteger)offset limit:(NSUInteger)limit {
    if (offset > NSUIntegerMax - data.length || _base > NSUIntegerMax - _bytes.length) return NO;
    const NSUInteger end = offset + data.length;
    const NSUInteger known = _base + _bytes.length;
    if (offset > known) return NO;  // never classify a frame with a hole
    if (end <= _base) return YES;
    if (end - _base > limit) return NO;
    const uint8_t *input = data.bytes;
    const NSUInteger from = MAX(offset, _base);
    const NSUInteger until = MIN(end, known);
    if (until > from && memcmp(input + from - offset, (const uint8_t *)_bytes.bytes + from - _base,
                              until - from)) return NO;
    if (end > known) [_bytes appendBytes:input + MAX(known, offset) - offset length:end - MAX(known, offset)];
    return YES;
}

- (void)consume:(NSUInteger)count {
    [_bytes replaceBytesInRange:NSMakeRange(0, count) withBytes:NULL length:0];
    _base += count;
}
@end
