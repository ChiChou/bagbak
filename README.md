# bagbak

Yet another frida based App decryptor. Requires jailbroken iOS device and [frida.re](https://www.frida.re/)

![demo](images/screenshot.gif)

*The name of this project doesn't have any meaning. I was just listening to that song while typing.*

## Prerequisites

### On device

* [frida.re](https://www.frida.re/docs/ios/)

That's all. No SSH required.

### On desktop

* [node.js](https://nodejs.org/) 14.x
* `zip` command (optional). We'll generate an ipa archive when this command is avaliable

That's all. Npm can handle all dependencies.

### Windows Compatibility

* Before `frida@12.5.5` it was unable to connect device via USB (ref: [12.5 release note](https://frida.re/news/2019/05/15/frida-12-5-released/)). Please use up-to-date frida to overcome this;
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
   -H, --host <host>      hostname
   -u, --uuid <uuid>      uuid of USB device
   -o, --output <output>  output directory
   -f, --override         override existing
   -e, --executable-only  dump executables only
   -z, --zip              create zip archive (ipa)
   -h, --help             output usage information
```

## Release Note

v1.6.0: fix [a long standing bug](https://github.com/ChiChou/bagbak/issues/46) that may cause serialization failure

## 捐助

如果觉得项目有帮助，可以通过支付宝和其他渠道打赏，金额随意

[Become a Patreon](http://patreon.com/codecolorist) Make donation

## 国内用户 frida 安装失败问题

请参考 [使用国内镜像加速安装](https://github.com/chaitin/passionfruit/wiki/%E4%BD%BF%E7%94%A8%E5%9B%BD%E5%86%85%E9%95%9C%E5%83%8F%E5%8A%A0%E9%80%9F%E5%AE%89%E8%A3%85#%E9%A2%84%E7%BC%96%E8%AF%91%E5%8C%85%E5%A4%B1%E8%B4%A5)
