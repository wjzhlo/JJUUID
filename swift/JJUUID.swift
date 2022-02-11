//
//  JJUUID.swift
//
//  Created by Jero on 2022/2/11.
//

/*
 
 ## 获取设备唯一标识的方式（资料均来自网络，只是简单概况了一下）
  
 一：iOS 2 版本以后UIDevice提供一个获取设备唯一标识符的方法uniqueIdentifier，通过该方法我们可以获取设备的序列号，这个也是目前为止唯一可以确认唯一的标示符。
 许多开发者把UDID跟用户的真实姓名、密码、住址、其它数据关联起来，为了避免用户的隐私数据泄露，苹果在iOS 5 废除该方式。现在应用试图获取UDID已被禁止且不允许上架。
  
 二：通过 IDFA（广告id）方式来识别用户的话，它有时候会获取不到值，因此也行不通。
  
 三：通过 IDFV（应用提供商）方式来识别用户的话，如果用户将属于此应用提供商的所有App卸载，则idfv的值会被重置，因此也行不通。
  
 四：使用 WiFi的MAC地址在 iOS 7 也被封杀了。
  
 五：KeyChain，也是目前比较合理、可行的一种方式。
  
 ## 实现与优势
  
 系统类 NSUUID 有提供生成随机不重复的字符串方法，通过将该随机字符串保存到iOS设备的钥匙串里面。不论是重启手机或卸载APP重装，只要指定的钥匙串没有被删除，
 就算是重启手机或卸载APP再重新安装，都能获取到同一个值，只有刷机或恢复出厂设置才会变（钥匙串信息被清空，获取不到，同名钥匙串被写入新值）。

 ## 使用方式

 let uuid = JJUUID.uuid()
 
 */

import Foundation

// 导入头文件
import Security

struct JJUUID {
    
    static func uuid() -> String? {
        
        let uuidKey = (Bundle.main.bundleIdentifier ?? "bundleIdentifier") + "_UUID"
        let saveKey = uuidKey + "_isSaveOK"
        var uuid = UserDefaults.standard.string(forKey: uuidKey)
        let isSaveOK = UserDefaults.standard.bool(forKey: saveKey)
        
        // 本地已经保存过uuid，返回uuid
        if let uuid = uuid {
            // keychain标记的是写入失败，更新标记
            if isSaveOK == false {
                UserDefaults.standard.set(true, forKey: saveKey)
            }
            return uuid
        }
        
        // 生成一个用于查询的可变字典
        var queryDic: [CFString : Any] = [:]
        
        // 添加需要获取的键值和类属性
        queryDic[kSecClass] = kSecClassGenericPassword // 表明为一般密码可能是证书或者其他东西
        queryDic[kSecReturnData] = kCFBooleanTrue // 返回Data类型数据
        queryDic[kSecAttrAccount] = uuidKey // 需要查询的值
        
        // 查询
        var status: OSStatus = -1
        var result: CFTypeRef? = nil
        status = SecItemCopyMatching(queryDic as CFDictionary, &result) //核心API 查找是否匹配和返回值
        
        // 查询成功，将结果转换成字符串
        if status == errSecSuccess, let cfData = result as? Data {
            uuid = String(data:cfData, encoding:.utf8)
        }
        // 查询失败，错误处理
        else {
            // 本地没有uuid，生成一个uuid备用（为兼容复杂格式，去掉"-"符号）
            if uuid == nil {
                uuid = NSUUID().uuidString.replacingOccurrences(of: "-", with: "")
            }
            // uuid转换成data类型
            let uuidData = uuid!.data(using: .utf8)
            // 键值不存在，直接保存
            if status == errSecItemNotFound {
                queryDic[kSecValueData] = uuidData
                status = SecItemAdd(queryDic as CFDictionary, nil)
            }
            // 其他错误直接更新
            else {
                var updateDict = queryDic
                updateDict[kSecValueData] = uuidData
                status = SecItemUpdate(queryDic as CFDictionary, updateDict as CFDictionary)
                // 更新失败，尝试删除已有的值。删除成功后，重新添加uuid
                if status != errSecSuccess {
                    status = SecItemDelete(queryDic as CFDictionary)
                    if status == errSecSuccess {
                        queryDic[kSecValueData] = uuidData
                        status = SecItemAdd(queryDic as CFDictionary, nil)
                    }
                }
            }
        }
        
        // 同步到本地
        UserDefaults.standard.set(uuid, forKey: uuidKey)
        UserDefaults.standard.set(status == errSecSuccess, forKey: saveKey)
        
        return uuid
    }
}
