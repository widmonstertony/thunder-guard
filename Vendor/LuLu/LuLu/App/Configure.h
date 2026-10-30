//
//  Configure.h
//  LuLu
//
//  Created by Patrick Wardle on 2/6/24.
//  Copyright © 2024 Objective-See. All rights reserved.
//

#ifndef Configure_h
#define Configure_h

@import Foundation;

@interface Configure : NSObject

//quit
// 'deactivateExtension': YES to also deactivate/unregister the system extension (uninstall);
//  NO to leave it registered/approved (quit & upgrade) so updates don't require re-approval
-(void)quit:(BOOL)deactivateExtension;

//install
-(BOOL)install;

//upgrade
-(BOOL)upgrade;

//uninstall
-(BOOL)uninstall;

@end

#endif /* Configure_h */
