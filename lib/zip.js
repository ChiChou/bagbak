const { spawn } = require('child_process')
const os = require('os')



async function zipCommand(output, folder) {
  const installed = (cmd) =>
    new Promise((resolve, reject) =>
      spawn(os.platform() === 'win32' ? 'where.exe' : 'which', [cmd])
        .on('error', reject)
        .on('close', code => code === 0 ? resolve() : reject()))

  const scheme = {
    '7z': ['a', output, folder],
    zip: ['-r', output, folder],
    powershell: ['Compress-Archive', '-Force', folder, output]
  }

  for (const [exec, args] of Object.entries(scheme)) {
    try {
      await installed(exec)
      return [exec, args]
    } catch(_) {

    }
  }

  console.error('Unable to create Zip archive')
  console.error('Neither 7z nor zip is installed, or you forgot to add them to PATH.')
  throw new Error('external zip command not found')
}

module.exports = async function(output, folder, cwd) {
  const [exec, args] = await zipCommand(output, folder)
  const opt = { stdio: 'inherit', cwd }
  return new Promise((resolve, reject) => {
    spawn(exec, args, opt)
      .on('error', reject)
      .on('close', (code, sig) => code ? reject(`command exited with code ${code} (${sig})`) : resolve())
  })
}
