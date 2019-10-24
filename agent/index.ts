if (typeof CModule === 'undefined')
  throw new Error('Your frida does not support CModule. Version: ' + Frida.version)

import { dump, prepare } from './dump';
import environ from './env';
import { plugins, launchAll, jetsam } from './pkd';
import { launch, stop } from './launchd';
import { skipPkdValidationFor } from './pluginkit';

Process.setExceptionHandler(ex => {
  console.error('Process crash:')
  console.error(ex)
});

rpc.exports = {
  dump,
  prepare,
  environ,

  plugins,
  launchAll,

  // pkd
  launch,
  stop,
  skipPkdValidationFor,
  jetsam,

}
