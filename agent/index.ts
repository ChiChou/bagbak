if (typeof CModule === 'undefined')
  throw new Error('Your frida does not support CModule. Version: ' + Frida.version)

import { dump, prepare } from './dump';
// import { toNSObject } from './nsdict';
import environ from './env';
import { plugins } from './pkd';
import { launch, stop } from './launchd';

rpc.exports = {
  dump,
  prepare,
  environ,
  plugins,

  // pkd
  launch,
  stop,

  // test() {
  //   const a = toNSObject({
  //     foo: 'bar',
  //     bar: 2,
  //     aaa: null,
  //     ddd: false,
  //     ccc: true
  //   });
  //   console.log(a)
  // }
}
