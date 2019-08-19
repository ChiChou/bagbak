# frida-ipa-dump

Yet another frida based iOS dumpdecrypted

Tested on macOS, supports both Python2 and Python3.

Recommended frida version: > 12.6

## Configuration

**No SSH required**. Just `pip install frida`

## Example

```
➜  frida-ipa-dump git:(master) ./dump.py hackertracker
[info] attaching to target
[info] decrypting module hackertracker
[info] compressing archive: /private/var/mobile/Containers/Data/Application/0F2B22A7-E2E3-4AAB-A183-F65520E8471F/tmp/ensa8nhyzt6.ipa
[info] done /private/var/mobile/Containers/Data/Application/0F2B22A7-E2E3-4AAB-A183-F65520E8471F/tmp/ensa8nhyzt6.ipa
[info] start transfering
[info] downloaded 4.00MiB of 7.79MiB, 51.33%
[info] downloaded 7.79MiB of 7.79MiB, 100.00%
[info] transfer complete
Output: hackertracker.ipa
```

## FAQ

Use `--verbose` to see full logs.

WatchOS related files may cause reinstallation failure, so we'll skip such files by default.

To preserve WatchOS binaries, use `--keep-watch` switch.

### `frida.NotSupportedError: unexpected error while probing dyld of target process`

Double click home, swipe up to kill the App, retry

### `frida.InvalidOperationError: script is destroyed`

App unexpectly crashed. This will only happen when App is launched by frida.

Start the app on device, wait for the initialization, then retry.

### `frida.ProtocolError: unable to communicate with remote frida-server; please ensure that major versions match and that the remote Frida has the feature you are trying to use`

`pip install -U frida`
