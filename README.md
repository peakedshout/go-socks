***
# go-socks
###### *A tool library developed based on golang that supports socks4/4a/5 protocol and supports CONNECT/BIND/UDPASSOCIATE operations.*
***
### [简体中文](./README_CN.md)/English
***
### Declaration
- The standards used in socks5 are rfc1929 and rfc1928, where CONNECT has been tested by (golang.org/x/net/proxy)proxy.SOCKS5.
- The standard adopted by socks4/4a is a public standard (I don't know which rfc was adopted by socks4/4a compared to socks5, but I found a more reliable document, if you know which rfc, please let me know).
- Although this library, I have done a little bit of freedom, it is obviously not for everyone, if you have better ideas or suggestions, or if you think my library implementation is wrong, please file an issue and fuck me!
- Inevitably, the library has been refactored, incorporating some of my new thinking, and some of the original APIs have also been refactored, but it has also become more powerful and freer.
- If you find it useful, please give us ✨.
***
## What can go-socks do?
- go-socks integrates socks4, socks4a and method of socks5 support the CONNECT/BIND/UDPASSOCIATE operations
- The library in the authentication, configuration has a good degree of freedom, is based on socks server as the center for expansion
***
## Why is this thing here?
- I tried to whore the existing socks library in golang, but I found that it basically only implements CONNECT, and apparently, most people only use CONNECT
- But for me, it's puzzling, why didn't anyone implement BIND and UDPASSOCIATE? (This prevented me from copying my homework)
- So I read what was available online and tested it.
***
## How to use it?
- ``go get github.com/peakedshout/go-socks``
- Detailed tutorials can be found [here](./_examples)
***
## TODO
- [x] CONNECT/BIND/UDPASSOCIATE
- [x] socks4/4a/5
- [x] Better auth support
- [x] Custom channels
- [x] Customizing relay
- [ ] Command line support
- [ ] Easier to use?
***
## Projects that use the library
- No, if you use it and want to be included in the list, you can contact me.
***
## Contrast v 1
- Updated UDPASSOCIATE implementation logic (see [here](https://github.com/peakedshout/go-pandorasbox/tree/master/xnet/proxy/socks) for details)
- Refactored the writing method to make the code style closer to net
- Extremely adopts callback implementation, with more powerful functions and freer operations.
- Use callback implementation to solve channel problems and authentication problems
- Refactoring caused the author to lose a lot of hair (became stronger?)
- One step closer to the most powerful go-socks library
***