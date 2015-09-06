//
//  NSString+LcAESRSA.h
//  TEST
//
//  Created by StephenZhu on 15/8/27.
//  Copyright (c) 2015年 StephenZhu. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface LcAESRSA : NSObject

- (NSMutableDictionary*)LcEncrypt:(NSDictionary*)EncryptDic;
- (NSMutableDictionary*)LcDecode:(NSDictionary*)EncryptDic;
@end
