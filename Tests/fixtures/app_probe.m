#import <Foundation/Foundation.h>
#include <stdio.h>
#include <string.h>

// Use the same signed executable for ordinary HTTPS and the peer test.
int run_peer_fixture(int argc, char **argv);

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 3 || strcmp(argv[1], "--https") != 0) return run_peer_fixture(argc, argv);
        NSURL *url = [NSURL URLWithString:@(argv[2])];
        if (![url.scheme.lowercaseString isEqualToString:@"https"] || !url.host.length) return 64;
        NSURLSessionConfiguration *settings = NSURLSessionConfiguration.ephemeralSessionConfiguration;
        settings.timeoutIntervalForRequest = 12;
        settings.timeoutIntervalForResource = 15;
        NSURLSession *session = [NSURLSession sessionWithConfiguration:settings];
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block NSInteger status = 0;
        __block NSUInteger size = 0;
        __block BOOL secure = NO;
        [[session dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (!error && [response isKindOfClass:NSHTTPURLResponse.class]) {
                status = ((NSHTTPURLResponse *)response).statusCode;
                size = data.length;
                secure = [response.URL.scheme.lowercaseString isEqualToString:@"https"];
            }
            dispatch_semaphore_signal(done);
        }] resume];
        long waitResult = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 18 * NSEC_PER_SEC));
        [session invalidateAndCancel];
        if (waitResult == 0 && secure && status >= 200 && status < 300 && size > 0) {
            printf("HTTPS %ld, %lu bytes\n", (long)status, (unsigned long)size);
            return 0;
        }
        fprintf(stderr, "HTTPS did not complete (status %ld)\n", (long)status);
        return 1;
    }
}
