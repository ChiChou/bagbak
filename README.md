# bagbak

Yet another frida based App decryptor. Requires jailbroken iOS device and [frida.re](https://www.frida.re/)

![demo](images/screen.gif)

*The name of this project doesn't have any meaning. I was just listening to that song while typing.*

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
  -o, --output <output>  ipa filename
  -h, --help             display help for command
```

## 国内用户 frida 安装失败问题

[使用国内镜像加速安装](https://github.com/chaitin/passionfruit/wiki/%E4%BD%BF%E7%94%A8%E5%9B%BD%E5%86%85%E9%95%9C%E5%83%8F%E5%8A%A0%E9%80%9F%E5%AE%89%E8%A3%85#%E9%A2%84%E7%BC%96%E8%AF%91%E5%8C%85%E5%A4%B1%E8%B4%A5)
