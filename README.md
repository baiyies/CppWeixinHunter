# CppWeixinHunter
微信内存信息提取 c++实现。体现微信"小而美"的设计理念。可获取自己电脑上已登录微信的微信号，wxid，手机号，sqlite解密密钥。

# 原理
通过c++实现的Sunday模式匹配算法。从内存中快速搜索指定数据。获取基址+偏移量与特征，从而达到微信版本每次更新不需要重新查找地址。

![image](https://raw.githubusercontent.com/baiyies/CppWeixinHunter/main/img/weixin.png)

# 参考项目 
https://github.com/x1hy9/WeChatUserDB
