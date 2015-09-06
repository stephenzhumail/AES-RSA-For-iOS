//
//  AppDelegate.m
//  AES_RSA
//
//  Created by StephenZhu on 15/8/27.
//  Copyright (c) 2015年 StephenZhu. All rights reserved.
//

#import "AppDelegate.h"
#import "LcAESRSA.h"
#import "SBJson.h"
#import "GTMBase64.h"
#import "NSData+AES256.h"
@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSString *str = [NSData AES256EncryptWithPlainText:@"1" key:@"11111111111111111111111111111111"];
    NSLog(@"%@",str);
    NSDictionary *stuDic = [NSDictionary dictionaryWithObjectsAndKeys:
                                   @"1",@"lastDaysIncome",
                                   @"2",@"totalIncome",
                                   @"3",@"lastDayThousandsIncome",
                                   @"4",@"totalMoney",
                                   @"5",@"availableMoney",
                                   nil];
    NSLog(@"\r加密前：%@",stuDic);
    LcAESRSA *test = [LcAESRSA new];
    NSMutableDictionary *dic = [test LcEncrypt:stuDic];
    NSLog(@"\r加密后：%@",dic);
    SBJsonWriter *write = [[SBJsonWriter alloc]init];
    NSLog(@"\r加密后的json：%@",[write stringWithObject:dic]);
    NSMutableDictionary *dic1 = [test LcDecode:dic];
    NSLog(@"\r解密后：%@",dic1);
    
    
    
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
