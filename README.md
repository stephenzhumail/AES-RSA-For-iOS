# AES-RSA
iOS，安全加密。采用RSA签名和AES随机秘钥加密，AES的随机秘钥采用RSA加密。

`````
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
`````
