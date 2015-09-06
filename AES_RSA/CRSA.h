//
//  CRSA.h
//  AES_RSA
//
//  Created by StephenZhu on 15/8/27.
//  Copyright (c) 2015年 StephenZhu. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/pem.h>
#import <openssl/err.h>
#import <openssl/rsa.h>


typedef enum {
    KeyTypePublic,
    KeyTypePrivate
}KeyType;

typedef enum {
    RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
}RSA_PADDING_TYPE;

@interface CRSA : NSObject{
    RSA *_rsa;
}
+ (id)shareInstance;
- (BOOL)importRSAKeyWithType:(KeyType)type;
- (int)getBlockSizeWithRSA_PADDING_TYPE:(RSA_PADDING_TYPE)padding_type;
- (NSString *) encryptByRsa:(NSString*)content withKeyType:(KeyType)keyType;
- (NSString *) decryptByRsa:(NSString*)content withKeyType:(KeyType)keyType;
@end