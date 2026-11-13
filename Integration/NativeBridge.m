#import "NativeBridge.h"
#import "AppDelegate.h"
#import "Extension.h"

@implementation TGNativeBridge
+ (void)showRules {
    // The rule editor and XPC client are part of this same signed executable.
    [(AppDelegate *)NSApp.delegate showRules:nil];
}
+ (BOOL)filterEnabled {
    return [[[Extension alloc] init] isNetworkExtensionEnabled];
}
@end
