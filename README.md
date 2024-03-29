
## 获取设备唯一标识的方式

> 资料均来自网络，只是简单概况了一下。
 
一：iOS 2 版本以后UIDevice提供一个获取设备唯一标识符的方法uniqueIdentifier，通过该方法我们可以获取设备的序列号，这个也是目前为止唯一可以确认唯一的标示符。许多开发者把UDID跟用户的真实姓名、密码、住址、其它数据关联起来，为了避免用户的隐私数据泄露，苹果在iOS 5 废除该方式。现在应用试图获取UDID已被禁止且不允许上架。
 
二：通过 IDFA（广告id）方式来识别用户的话，它有时候会获取不到值，因此也行不通。
 
三：通过 IDFV（应用提供商）方式来识别用户的话，如果用户将属于此应用提供商的所有App卸载，则idfv的值会被重置，因此也行不通。
 
四：使用 WiFi的MAC地址在 iOS 7 也被封杀了。
 
五：KeyChain，也是目前比较合理、可行的一种方式。
 
## 实现与优势
 
系统类 NSUUID 有提供生成随机不重复的字符串方法，通过将该随机字符串保存到iOS设备的钥匙串里面。不论是重启手机或卸载APP重装，只要指定的钥匙串没有被删除，就算是重启手机或卸载APP再重新安装，都能获取到同一个值，只有刷机或恢复出厂设置才会变（钥匙串信息被清空，获取不到，同名钥匙串被写入新值）。

## 使用方式

```
let uuid = JJUUID.uuid()
```

### 其他备注

Swift 是由 Objective-C 代码改写而来，语言版本 Swift 5.2，XCode版本 13.2.1
