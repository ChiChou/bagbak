# bagbak

[![version](https://img.shields.io/npm/v/bagbak)]((https://www.npmjs.com/package/bagbak))
[![downloads](https://img.shields.io/npm/dm/bagbak)](https://www.npmjs.com/package/bagbak)
[![issues](https://img.shields.io/github/issues/chichou/bagbak)](https://github.com/chichou/bagbak/issues)
[![sponsers](https://img.shields.io/github/sponsors/chichou)](https://github.com/sponsors/chichou)
[![license](https://img.shields.io/github/license/chichou/bagbak)](LICENSE)

Yet another frida based App decryptor. Requires jailbroken iOS device and [frida.re](https://www.frida.re/)

Only tested on iOS 14 (unc0ver) and iOS 16 (checkm8). Dopamine seems to have issues on process spawn and I don't have such device to debug.

![demo](images/screen.gif)

*The name of this project doesn't have any meaning. I was just listening to that song while typing.*

[FAQ](https://github.com/ChiChou/bagbak/wiki#faq)

## Prerequisites

### On device

With Cydia:

* [frida.re](https://www.frida.re/docs/ios/)

Rootless:

If your are using rootless jailbreak, another project of mine [fruity-frida](https://github.com/ChiChou/fruity-frida/) might help. Use the `run-frida-server` to automatically download, deploy and run frida-server on your device.

### On desktop

* [node.js](https://nodejs.org/). If you have issues on `npm install`, your node.js might be either too new or too old. Try to use `nvm` to install a compatible version or download the correct installer.
* `zip` or `7z` command is needed to create zip archive. On most of the distros, you don't need to install them manually.

### Windows Compatibility

* Filesystem of iOS differs from Windows. If you are running bagbak on Windows, **some of the file attributes (e.g., executable bit) will be lost**, thus the repacked ipa may not be able to reinstall on your phone. But it does not matter if you only indend to do static analysis.

## Install

```
npm install -g bagbak
```

## Usage

bagbak [bundle id or name]

```
Options:
  -l, --list             list apps
  -U, --usb              connect to USB device (default)
  -R, --remote           connect to remote frida-server
  -D, --device <uuid>    connect to device with the given ID
  -H, --host <host>      connect to remote frida-server on HOST
  -f, --force            override existing files
  -d, --debug            enable debug output
  -r, --raw              dump raw app bundle to directory (no ipa)
  -o, --output <output>  ipa filename or directory to dump to
  -h, --help             display help for command
```

Environments variables:

* `DEBUG=1` enable debug output for troubleshooting
* `DEBUG_SCP=1` debug SCP protocol
* `SSH_USERNAME` username for iPhone SSH, default to `root`
* `SSH_PASSWORD` password for iPhone SSH, default to `alpine`
* `SSH_PORT` port for iPhone SSH. If not given, bagbak will scan port 22 (OpenSSH) and port 44 (Dropbear)


Example:

* `bagbak -l` to list all apps
* `bagbak --raw Chrome` to dump the app to current directory
* `bagbak com.google.chrome.ios` to dump app to `com.google.chrome.ios-[version].ipa`

## 国内用户 frida 安装失败问题

[使用国内镜像加速安装](https://github.com/chaitin/passionfruit/wiki/%E4%BD%BF%E7%94%A8%E5%9B%BD%E5%86%85%E9%95%9C%E5%83%8F%E5%8A%A0%E9%80%9F%E5%AE%89%E8%A3%85#%E9%A2%84%E7%BC%96%E8%AF%91%E5%8C%85%E5%A4%B1%E8%B4%A5)

<p align="center">想看更多中文技术分享？欢迎关注我的公众号</p>
<p align="center"><image src="images/weixin.jpg" width="240" /></p>
