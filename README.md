# bagbak

[![version](https://img.shields.io/npm/v/bagbak)](https://www.npmjs.com/package/bagbak)
[![downloads](https://img.shields.io/npm/dm/bagbak)](https://www.npmjs.com/package/bagbak)
[![issues](https://img.shields.io/github/issues/chichou/bagbak)](https://github.com/chichou/bagbak/issues)
[![sponsers](https://img.shields.io/github/sponsors/chichou)](https://github.com/sponsors/chichou)
[![license](https://img.shields.io/github/license/chichou/bagbak)](LICENSE)

Yet another frida based App decryptor. Requires jailbroken iOS device and [frida.re](https://www.frida.re/)

Tested on iOS 15 (Dopamine) and iOS 16 (palera1n).

*The name of this project doesn't have any meaning. I was just listening to that song while typing.*

## Prerequisites

**Note:** bagbak@5 requires frida@17. If your frida-server is v16, use `npm install -g bagbak@4` instead.

### On device

* [frida.re](https://www.frida.re/docs/ios/)

### On desktop

- [node.js](https://nodejs.org/). 
- `npm install -g bagbak`

## Usage

bagbak [bundle id or name]

```
Options:
  -l, --list                list apps
  -j, --json                output as json (only works with --list)
  -U, --usb                 connect to USB device (default)
  -R, --remote              connect to remote frida-server
  -D, --device <uuid>       connect to device with the given ID
  -H, --host <host>         connect to remote frida-server on HOST
  -d, --debug               enable debug output
  -o, --output <output>     ipa filename or directory to dump to
  --remove-keys <keys>      additional Info.plist keys to remove (comma-separated)
  -h, --help                display help for command
```

Dump modes (second argument):

* `all` (default) — full IPA with all binaries decrypted
* `main` (alias: `app`) — decrypt main app binary only
* `extensions` (aliases: `ext`, `exts`) — decrypt extension binaries only
* `binaries` (aliases: `bin`, `executables`) — decrypt all binaries, output as zip

Environments variables:

* `DEBUG=1` enable debug output for troubleshooting

Example:

* `bagbak -l` to list all apps
* `bagbak com.google.chrome.ios` to dump app to `com.google.chrome.ios-[version].ipa`
* `bagbak com.google.chrome.ios main` to dump only the main binary
* `bagbak --remove-keys UISupportedDevices,UIRequiredDeviceCapabilities com.google.chrome.ios` to remove extra Info.plist keys
