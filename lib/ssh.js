const net = require('net')
const frida = require('frida')
const { Client } = require('ssh2')

const TIMEOUT = 2000

/**
 * 
 * @param {frida.Device} device 
 * @returns {Number}
 */
async function scan(device) {
  const canidates = [22, 44]
  for (const port of canidates) {
    const channel = await device.openChannel(`tcp:${port}`);
    const yes = await new Promise((resolve) => {
      channel.once('data', data => resolve(data.readUInt32BE() === 0x5353482d)); // SSH-
      setTimeout(() => resolve(false), TIMEOUT)
    })
    if (yes) return port
  }
  throw Error('port not found')
}

/**
 * 
 * @param {frida.Device} device
 * @returns {Promise<net.Server>}
 */
async function iproxy(device) {
  const port = await scan(device);
  return new Promise((resolve) => {
    const server = net.createServer(async (socket) => {
      const channel = await device.openChannel(`tcp:${port}`);
      socket.pipe(channel);
      channel.pipe(socket);
      socket.on('close', () => {
        channel.unpipe();
        socket.unpipe();
        socket.unref();
        channel.destroy();
      }).on('error', console.error.bind(console));
    }).listen(0, () => {
      resolve(server);
    });
  });
}

/**
 * 
 * @param {frida.Device} device 
 * @param {string} path 
 */
async function ls(device, path) {
  const proxy = await iproxy(device)
}
