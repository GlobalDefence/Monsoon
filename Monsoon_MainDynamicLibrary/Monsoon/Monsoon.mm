//
//  Monsoon.m
//  Monsoon
//
//  Created by Meirtz on 14-2-3.
//  Copyright (c) 2014年 __MyCompanyName__. All rights reserved.
//

#import "Monsoon.h"


#include <stdio.h>
#include <objc/runtime.h>
#import <Foundation/Foundation.h>

#define APP_ID "monsoon.support.mach.port"
#define MACH_PORT_NAME APP_ID

@interface SBAppSliderController : UIViewController
{
    NSMutableArray *_appList;
}

- (NSArray *)applicationList;
- (void)_quitAppAtIndex:(unsigned int)arg1;
- (void)forceDismissAnimated:(BOOL)arg1;

@end

static IMP sOriginalImp = NULL;

@implementation Monsoon

+ (void)load{
    Class originalClass = NSClassFromString(@"SBAppSliderController");  //%hook SBAppSliderController
    Method originalMeth = class_getInstanceMethod(originalClass, @selector(switcherWasPresented:));
    sOriginalImp = method_getImplementation(originalMeth);
	Method replacementMeth = class_getInstanceMethod(NSClassFromString(@"Monsoon"), @selector(patchedLaunch:));
	method_exchangeImplementations(originalMeth, replacementMeth);
    
}

- (void)patchedLaunch:(_Bool)arg1{
    sOriginalImp(self, @selector(switcherWasPresented:), self);   //%orig
    UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"INJECTED" message:@"Method has been replaced by objc_runtime dynamic library\nDYLD_INSERT_LIBRARIES=libMonsoon.dylib" delegate:nil cancelButtonTitle:@"OK" otherButtonTitles: nil];
    
    [alert show];
}
@end
