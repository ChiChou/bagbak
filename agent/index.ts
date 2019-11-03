if (typeof CModule === 'undefined')
  throw new Error('Your frida does not support CModule. Version: ' + Frida.version)

import { dump, prepare, base } from './dump';
import environ from './env';
import { skipPkdValidationFor, jetsam } from './pkd';
import { launchAll, plugins } from './pluginkit';

// Process.setExceptionHandler(ex => {
//   console.error('Process crash:')
//   console.error(ex)
// });

rpc.exports = {
  dump,
  prepare,
  environ,
  plugins,
  launchAll,
  base,

  // pkd
  skipPkdValidationFor,
  jetsam,

}
