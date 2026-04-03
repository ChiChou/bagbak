# bagbak

[![version](https://img.shields.io/npm/v/bagbak)](https://www.npmjs.com/package/bagbak)
[![downloads](https://img.shields.io/npm/dm/bagbak)](https://www.npmjs.com/package/bagbak)
[![issues](https://img.shields.io/github/issues/chichou/bagbak)](https://github.com/chichou/bagbak/issues)
[![sponsers](https://img.shields.io/github/sponsors/chichou)](https://github.com/sponsors/chichou)
[![license](https://img.shields.io/github/license/chichou/bagbak)](LICENSE)

又一个基于 Frida 的 App 解密工具。需要越狱的 iOS 设备和 [frida.re](https://www.frida.re/)

已在 iOS 15 (Dopamine) 和 iOS 16 (palera1n) 上测试通过。

*这个项目的名字没有任何含义，我写代码的时候正在听那首歌。*

## 环境要求

**注意：** bagbak@5 需要 frida@17。如果你的 frida-server 是 v16，请使用 `npm install -g bagbak@4`。

### 设备端

* [frida.re](https://www.frida.re/docs/ios/)

### 电脑端

- [node.js](https://nodejs.org/)
- `npm install -g bagbak`

## 使用方法

bagbak [bundle id 或应用名称]

```
Options:
  -l, --list                列出所有应用
  -j, --json                以 JSON 格式输出 (仅配合 --list 使用)
  -U, --usb                 连接 USB 设备 (默认)
  -R, --remote              连接远程 frida-server
  -D, --device <uuid>       连接到指定 ID 的设备
  -H, --host <host>         连接到指定主机的远程 frida-server
  -d, --debug               启用调试输出
  -o, --output <output>     ipa 文件名或输出目录
  --remove-keys <keys>      额外需要移除的 Info.plist 键 (逗号分隔)
  -h, --help                显示帮助信息
```

解密模式 (第二个参数):

* `all` (默认) — 完整 IPA，解密所有二进制文件
* `main` (别名: `app`) — 仅解密主应用二进制文件
* `extensions` (别名: `ext`, `exts`) — 仅解密扩展二进制文件
* `binaries` (别名: `bin`, `executables`) — 解密所有二进制文件，输出为 zip

环境变量:

* `DEBUG=1` 启用调试输出

示例:

* `bagbak -l` 列出所有应用
* `bagbak com.google.chrome.ios` 解密应用并输出到 `com.google.chrome.ios-[version].ipa`
* `bagbak com.google.chrome.ios main` 仅解密主应用二进制文件
* `bagbak --remove-keys UISupportedDevices,UIRequiredDeviceCapabilities com.google.chrome.ios` 移除额外的 Info.plist 键

<p align="center">想看更多中文技术分享？欢迎关注我的公众号</p>
<p align="center"><image src="images/weixin.jpg" width="240" /></p>