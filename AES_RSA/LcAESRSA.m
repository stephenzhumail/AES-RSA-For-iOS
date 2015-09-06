//
//  NSString+LcAESRSA.m
//  TEST
//
//  Created by StephenZhu on 15/8/27.
//  Copyright (c) 2015年 StephenZhu. All rights reserved.
//

#import "LcAESRSA.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import "CRSA.h"
#import "SBJson.h"
#import "GTMBase64.h"
#import "NSData+AES256.h"
#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH  // SHA-1消息摘要的数据位数160位
@implementation LcAESRSA
/**
 *  加密
 *
 *  @param EncryptDic 明文报文
 *
 *  @return 密文报文
 */
- (NSMutableDictionary*)LcEncrypt:(NSDictionary*)EncryptDic
{
    NSMutableDictionary *resultDic = [[NSMutableDictionary alloc]initWithCapacity:1];
    //step1 对报文数据源排序a->z
    NSMutableArray *sortedArray = [self sortDictionary:EncryptDic];
    //step2 取出排序过后数组的value，拼成string
    NSMutableArray *arrayOfValues = [NSMutableArray arrayWithArray:sortedArray];
    NSString *paramValue = [arrayOfValues componentsJoinedByString:@""];
    //step3 根据RAS私有密钥签名业务请求参数值字符串(paramValue),生成基于SHA1的RSA数字签名
    CRSA *t = [CRSA shareInstance];
    NSString *sign = [t encryptByRsa:paramValue withKeyType:KeyTypePrivate];
    //step4 将签名放入原报文
    NSMutableDictionary *dicWithSign = [NSMutableDictionary dictionaryWithDictionary:EncryptDic];
    [dicWithSign setObject:sign forKey:@"sign"];
    //step5 随机生成16位数字和字母组成的
    NSString *merchantAesKey = [LcAESRSA set32bitString:16];
    NSLog(@"\rAES key :%@",merchantAesKey);
    //step6 用16位随机码加密含有签名的报文
    SBJsonWriter * parser = [[SBJsonWriter alloc]init];
    NSString * realdata = [parser stringWithObject:dicWithSign];
    NSString *Stringdata = [NSData AES256EncryptWithPlainText:realdata key:merchantAesKey];
    //step7 使用 RSA 加密 merchantAesKey 生成密钥密文:
    NSString *Stringencryptkey = [t encryptByRsa:merchantAesKey withKeyType:KeyTypePublic];
    [resultDic setObject:Stringdata forKey:@"data"];
    [resultDic setObject:Stringencryptkey forKey:@"encryptKey"];
    return resultDic;
}

/**
 *  排序字典，按a->z
 *
 *  @param dic 数据源-字典
 *
 *  @return 排序过后的字典
 */
- (NSMutableArray*)sortDictionary:(NSDictionary*)dic
{
    NSArray *myKeys = [dic allKeys];
    NSArray *sortedKeys = [myKeys sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    NSMutableArray *sortedValues = [[NSMutableArray alloc] initWithCapacity:1];
    
    for(id key in sortedKeys) {
        id object = [dic objectForKey:key];
        [sortedValues addObject:object];
    }
    return sortedValues;
}

/**
 *  随机生成16位
 *
 *  @param size 1
 *
 *  @return 1
 */

+(NSString *)set32bitString:(int)size

{
    char data[size];
    for (int x=0;x<size;x++)
    {
        int randomint = arc4random_uniform(2);
        if (randomint == 0) {
            data[x] = (char)('A' + (arc4random_uniform(26)));
        }
        else
        {
            data[x] = (char)('0' + (arc4random_uniform(9)));
        }
        
    }
    
    return [[NSString alloc] initWithBytes:data length:size encoding:NSUTF8StringEncoding];
    
}
/**
 *  解密
 *
 *  @param EncryptStr 加密字符串
 *  @param EncryptKey 解密爻辞
 *
 *  @return 明文
 */

- (NSMutableDictionary*)LcDecode:(NSDictionary*)EncryptDic
{
    NSString *data = [EncryptDic valueForKey:@"data"];
    NSString *encryptkey = [EncryptDic valueForKey:@"encryptKey"];
    CRSA *t = [CRSA shareInstance];
    //step1:用 RSA 解密接口返回的密钥密文 encryptkey,获取 ybAesKey:
    NSString *AesKey = [t decryptByRsa:encryptkey withKeyType:KeyTypePrivate];
    //Step2:用 AesKey 将接口返回的业务密文 data 解密
    NSString *StringybRealData = [NSData AES256DecryptWithCiphertext:data key:AesKey];
    SBJsonParser * parser = [[SBJsonParser alloc] init];
    NSMutableDictionary *dicData = [parser objectWithString:StringybRealData];
    //Step3:将 dicData 中除了 sign 之外的参数按键排序,并将参数值拼成字符串 signData
    NSMutableDictionary *dicTmp = [NSMutableDictionary dictionaryWithDictionary:dicData];
    [dicTmp removeObjectForKey:@"sign"];
    
    NSMutableArray *sortedArray = [self sortDictionary:dicTmp];
    NSString *signData = [sortedArray componentsJoinedByString:@""];
    BOOL isRight = [self checkSign:signData entrySign:[dicData valueForKey:@"sign"]];
    if (isRight) {
        [dicData removeObjectForKey:@"sign"];
        return dicData;
    }
    else
    {
        return nil;
    }
    
//    return dicData;
}

- (BOOL)checkSign:(NSString*)signData entrySign:(NSString*)entrySign
{
    CRSA *t = [CRSA shareInstance];
    NSString * str = [t decryptByRsa:entrySign withKeyType:KeyTypePublic];
    if ([str isEqualToString:signData]) {
        return YES;
    }
    else
    {
        return NO;
    }
}
- (NSString *) decodeBase64:(NSString *) input{
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    data = [GTMBase64 decodeData:data];
    NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return string;
}

@end
