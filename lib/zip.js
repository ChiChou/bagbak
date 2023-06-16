import path from 'path';
import { spawn } from 'child_process';
import { platform } from 'os';

/**
 *
 * @param {import('fs').PathLike} output
 * @returns {Promise<[string, string[]]>}
 */
async function zipCommand(output) {
  const relative = 'Payload';
  const installed = (cmd) =>
    new Promise((resolve, reject) =>
      spawn(platform() === 'win32' ? 'where.exe' : 'which', [cmd])
        .on('error', reject)
        .on('close', (code) => (code === 0 ? resolve() : reject()))
    );

  const scheme = {
    '7z': ['a', output, relative],
    zip: ['-r', output, relative],
    powershell: ['Compress-Archive', '-Force', relative, output],
  };

  for (const [exec, args] of Object.entries(scheme)) {
    try {
      await installed(exec);
      return [exec, args];
    } catch (_) {}
  }

  console.error('Unable to create Zip archive');
  console.error(
    'Neither 7z nor zip is installed, or you forgot to add them to PATH.'
  );
  throw new Error('external zip command not found');
}

/**
 *
 * @param {import('fs').PathLike} output destination filename
 * @param {import('fs').PathLike} payload payload folder
 * @returns {Promise<void>}
 */
export default async function (output, payload) {
  const cwd = path.dirname(payload);
  const [exec, args] = await zipCommand(output);
  const opt = { stdio: 'inherit', cwd };
  return new Promise((resolve, reject) => {
    spawn(exec, args, opt)
      .on('error', reject)
      .on('close', (code, sig) =>
        code ? reject(`command exited with code ${code} (${sig})`) : resolve()
      );
  });
}
