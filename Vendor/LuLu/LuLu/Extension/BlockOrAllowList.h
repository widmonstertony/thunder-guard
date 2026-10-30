//
//  BlockOrAllowList.h
//  Extension
//
//  Created by Patrick Wardle on 11/6/20.
//  Copyright © 2020 Objective-See. All rights reserved.
//

@import Cocoa;
@import OSLog;
@import NetworkExtension;

NS_ASSUME_NONNULL_BEGIN

@interface BlockOrAllowList : NSObject

/* PROPERTIES */

//path
@property(nonatomic, retain)NSString* path;

//block list
@property(nonatomic, retain)NSMutableSet* items;

//modification time
@property(nonatomic, retain)NSDate* lastModified;

//timer to (re)load a remote list daily
// note: a single repeating source, so reloads don't stack
@property(nonatomic, strong)dispatch_source_t reloadTimer;


/* METHODS */

//init
// with a path
-(id)init:(NSString*)path;

//(re)load from disk
// returns YES if the list loaded (or there's nothing to load); NO on a fetch/read failure
-(BOOL)load:(NSString*)path;

//clear the list
// empties items & stops any (remote) reload timer
-(void)clear;

//should reload
// checks file modification time
-(BOOL)shouldReload;

//check if flow matches item on block list
-(BOOL)isMatch:(NEFilterSocketFlow*)flow;

@end

NS_ASSUME_NONNULL_END
