***
# go-socks
###### *一个基于golang开发的支持socks4/4a/5协议工具库，支持CONNECT/BIND/UDPASSOCIATE操作。*
***
### 简体中文/[English](./README.md)
***
### 声明
- socks5 采用的标准是rfc1929和rfc1928，其中CONNECT经过了(golang.org/x/net/proxy)proxy.SOCKS5的测试。
- socks4/4a 采用的标准是大众的标准（比起socks5，我不清楚socks4/4a采用是什么rfc，但我找到了可信度较高的文档，如果你知道是哪个rfc，请告诉我）
- 尽管该库，我做了一些自由度的操作，但显然不可能满足所有人，如果你有更好想法或建议，又或者是认为我的库实现错了，请提交issue来操我！
- 不可避免的，该库经过了重构，结合了本人一些新思考，一些原有的api也被重构，但也变得更强大和更自由。
- 如果你觉得好用，请给个✨。
***
## go-socks能做什么？
- go-socks集成了socks4、socks4a和socks5的方法，支持CONNECT/BIND/UDPASSOCIATE操作
- 该库的在认证、配置上有不错的自由度，是以socks server为中心进行拓展
***
## 为什么会出现这玩意？
- 我想白嫖现有的golang的socks库，但我发现基本只实现了CONNECT，显然，大部分人也只使用CONNECT
- 但对于我来说，感到了疑惑，为什么没人去实现BIND和UDPASSOCIATE？（这导致我无法抄作业）
- 所以我阅读网上现有的资料，经过测试实现了。
***
## 怎么使用？
- ``go get github.com/peakedshout/go-socks``
- 具体教程看[这里](./_examples)
***
## TODO
- [x] CONNECT/BIND/UDPASSOCIATE
- [x] socks4/4a/5
- [x] 更好的支持auth
- [x] 自定义信道
- [x] 自定义relay
- [ ] 命令行支持
- [ ] 更简单的使用？
***
## 使用该库的项目
- 没有，如果你使用了想上榜可以联系我。
***
## 对比v1
- 更新了UDPASSOCIATE实现逻辑（详细见[这里](https://github.com/peakedshout/go-pandorasbox/tree/master/xnet/proxy/socks)）
- 重构了写法，使代码风格更趋近于net
- 极端地采用回调式实现，功能更强大，操作更自由
- 利用回调式实现解决信道问题和认证问题
- 重构导致作者掉了不少头发（变得更强了？）
- 距离最强的go-socks库又更近一步
***