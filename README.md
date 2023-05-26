***
# go-socks
###### *A golang based development support socks4/4a/5 protocol tool library, support the CONNECT/BIND/UDPASSOCIATE operations, the supplementary relay tools.*
***
### [简体中文](./README_CN.md)/English
***
### Declaration
- The standards used in socks5 are rfc1929 and rfc1928, where CONNECT has been tested by (golang.org/x/net/proxy)proxy.SOCKS5.
- The standard adopted by socks4/4a is a public standard (I don't know which rfc was adopted by socks4/4a compared to socks5, but I found a more reliable document, if you know which rfc, please let me know).
- Although this library, I have done a little bit of freedom, it is obviously not for everyone, if you have better ideas or suggestions, or if you think my library implementation is wrong, please file an issue and fuck me!
- Inevitably, I included a library I wrote earlier as a relay extension, so if you don't like it, you don't have to use it. It won't hurt you.
- If you find it useful, please give us ✨.
***
## What can go-socks do?
- go-socks integrates socks4, socks4a and method of socks5 support the CONNECT/BIND/UDPASSOCIATE operations
- And it kindly comes with the relay tool
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
- [ ] Better auth support
- [ ] Custom channels
- [ ] Customizing relay
***
## Projects that use the library
- [cfc-proxyNet](https://github.com/peakedshout/cfc-proxyNet)
***