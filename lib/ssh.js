const frida = require('frida')
const { Client } = require('ssh2')
const { stdout } = require('process')

/**
 * 
 * @param {frida.Device} device 
 * @returns {Promise<Number>}
 */
async function scan(device) {
  const canidates = [22, 44]
  for (const port of canidates) {
    const channel = await device.openChannel(`tcp:${port}`);
    const yes = await new Promise((resolve) => {
      channel
        .once('data', data => {
          resolve(data.readUInt32BE() === 0x5353482d); // SSH-
          channel.destroy();
        }).once('error', () => {
          resolve(false);
        });
    })
    if (yes) return port
  }
  throw Error('port not found')
}

async function main() {
  const device = await frida.getUsbDevice();
  const port = await scan(device);
  const channel = await device.openChannel(`tcp:${port}`);

  /**
   * use ssh2 to list files
   */
  const conn = new Client();
  conn.on('ready', () => {
    conn.exec('ls', (err, stream) => {
      stream.pipe(stdout);
      stream.on('close', (code, signal) => {
        conn.end();
      })
    })
  }).connect({
    sock: channel,
    username: 'root',
    password: 'alpine'
  })
}

main()