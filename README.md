# frida-ipa
Yet another frida based iOS dumpdecrypted

## Configuration

No SSH required. Just `pip install frida`

## Example

```
➜  frida-ipa-dump git:(master) ./dump.py Edge -o ~/Downloads
[info] attaching to target
[info] decrypting module RubyBrowser
[info] decrypting module ConnectedDevices
[info] decrypting module Papyrus
[info] decrypting module PapyrusCore
[info] decrypting module PapyrusCoreCpp
[info] decrypting module RubySync
[warning] Module libswiftAVFoundation.dylib is not encrypted
[warning] Module libswiftContacts.dylib is not encrypted
[warning] Module libswiftCore.dylib is not encrypted
[warning] Module libswiftCoreAudio.dylib is not encrypted
[warning] Module libswiftCoreData.dylib is not encrypted
[warning] Module libswiftCoreFoundation.dylib is not encrypted
[warning] Module libswiftCoreGraphics.dylib is not encrypted
[warning] Module libswiftCoreImage.dylib is not encrypted
[warning] Module libswiftCoreLocation.dylib is not encrypted
[warning] Module libswiftCoreMedia.dylib is not encrypted
[warning] Module libswiftDarwin.dylib is not encrypted
[warning] Module libswiftDispatch.dylib is not encrypted
[warning] Module libswiftFoundation.dylib is not encrypted
[warning] Module libswiftMetal.dylib is not encrypted
[warning] Module libswiftObjectiveC.dylib is not encrypted
[warning] Module libswiftPhotos.dylib is not encrypted
[warning] Module libswiftQuartzCore.dylib is not encrypted
[warning] Module libswiftUIKit.dylib is not encrypted
[warning] Module libswiftsimd.dylib is not encrypted
[warning] Module libswiftos.dylib is not encrypted
[warning] unable to open file /var/containers/Bundle/Application/7506B185-DBEF-4004-BCDD-C645C3702286/RubyBrowser.app/SC_Info/Manifest.plist, skip
See Edge.ipa
```

## FAQ

WatchOS related files may cause reinstallation failure, so we'll skip such files by default.

To preserve WatchOS binaries, use `--keep-watch` switch.

### `frida.NotSupportedError: unexpected error while probing dyld of target process`

Double click home, swipe up to kill the App, retry

### `frida.InvalidOperationError: script is destroyed`

App unexpectly crashed. This will only happen when App is launched by frida.

Start the app on device, wait for the initialization, then retry.
