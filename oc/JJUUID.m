//
//  JJUUID.m
//
//  Created by Jero on 2020/6/16.
//

#import "JJUUID.h"
#import <Security/Security.h>

// 备注：只有刷机或恢复出厂设置UUID才会变

@implementation JJUUID

+ (NSString *)uuid {
    
    NSString *uuidKey = [NSString stringWithFormat:@"%@_UUID", [[NSBundle mainBundle] bundleIdentifier]];
    NSString *saveKey = [uuidKey stringByAppendingString:@"_isSaveOK"];
    NSString *uuid = [[NSUserDefaults standardUserDefaults] objectForKey:uuidKey];
    BOOL isSaveOK  = [[NSUserDefaults standardUserDefaults] boolForKey:saveKey];
    
    // 本地已经保存过uuid，且keychain也写入成功，直接返回uuid
    if (uuid.length > 10 && isSaveOK == YES) {
        return uuid;
    }
    
    // 本地已经保存过uuid，但标记是保存失败，更新标记并返回uuid
    if (uuid.length > 10 && isSaveOK == NO) {
        [[NSUserDefaults standardUserDefaults] setBool:YES forKey:saveKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        return uuid;
    }
    
    // 生成一个用于查询的可变字典
    NSMutableDictionary *queryDic = [NSMutableDictionary dictionary];
    
    // 添加需要获取的键值和类属性
    [queryDic setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass]; // 表明为一般密码可能是证书或者其他东西
    [queryDic setObject:(__bridge id)kCFBooleanTrue  forKey:(__bridge id)kSecReturnData];     // 返回Data类型数据
    [queryDic setObject:uuidKey forKey:(__bridge id)kSecAttrAccount]; // 需要查询的值
    
    // 查询
    OSStatus status = -1;
    CFTypeRef result = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)queryDic,&result);//核心API 查找是否匹配和返回值
    
    // 查询成功，将结果转换成字符串
    if (status == errSecSuccess) {
        uuid = [[NSString alloc] initWithBytes:[(__bridge_transfer NSData *)result bytes]
                                        length:[(__bridge NSData *)result length]
                                      encoding:NSUTF8StringEncoding];
    }else {// 查询失败，错误处理
        // 本地没有uuid，生成一个uuid备用（为兼容复杂格式，去掉"-"符号）
        if (uuid.length <= 0) { uuid = [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""]; }
        // uuid转换成data类型
        NSData *uuidData = [uuid dataUsingEncoding:NSUTF8StringEncoding];
        // 键值不存在，直接保存
        if (status == errSecItemNotFound) {
            [queryDic setObject:uuidData forKey:(__bridge id)kSecValueData];
            status = SecItemAdd((__bridge CFDictionaryRef)queryDic, NULL);
        }
        // 其他错误直接更新
        else {
            NSMutableDictionary *updateDict = [[NSMutableDictionary alloc] initWithDictionary:queryDic];
            [updateDict setObject:uuidData forKey:(__bridge id)kSecValueData];
            status = SecItemUpdate((__bridge CFDictionaryRef)queryDic, (__bridge CFDictionaryRef)updateDict);
             // 更新失败，尝试删除已有的值。删除成功后，重新添加uuid
             if (status != errSecSuccess) {
                 status = SecItemDelete((CFDictionaryRef)queryDic);
                 if (status == errSecSuccess) {
                     [queryDic setObject:uuidData forKey:(__bridge id)kSecValueData];
                     status = SecItemAdd((__bridge CFDictionaryRef)queryDic, NULL);
                 }
             }
        }
    }
    
    // 同步到本地
    [[NSUserDefaults standardUserDefaults] setObject:uuid forKey:uuidKey];
    [[NSUserDefaults standardUserDefaults] setBool:(status == errSecSuccess) forKey:saveKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    
    return uuid;
}

@end
