import frida from 'frida';
import path from 'path';

import { WriteStream, createReadStream, createWriteStream, promises as fsp } from 'fs';
import { Client } from 'ssh2';
import { promisify } from 'util';
import { Duplex } from 'stream';


/**
 * 
 * @param {frida.Device} device 
 * @returns 
 */
export async function scan(device) {
  const canidates = [22, 44]
  for (const port of canidates) {
    const ok = await device.openChannel(`tcp:${port}`)
      .then((channel) => new Promise((resolve) => {
        channel
          .once('data', data => {
            resolve(data.readUInt32BE() === 0x5353482d); // SSH-
            channel.destroy();
          })
          .once('error', () => {
            resolve(false);
          });
      }))
      .catch(() => false);

    if (ok) return port;
  }

  throw Error('Port not found. Target device must be jailbroken and with sshd running.');
}

/**
 * 
 * @param {frida.Device} device 
 * @param {string} user 
 * @param {string} password 
 * @returns {Promise<Client>}
 */
export async function connect(device, user = 'root', password = 'alpine') {
  const port = await scan(device);
  const channel = await device.openChannel(`tcp:${port}`);

  const client = new Client();
  return new Promise((resolve, reject) => {
    client
      .on('ready', () => resolve(client))
      .on('error', reject)
      .connect({
        sock: channel,
        username: user,
        password,
      });
  });
}


/**
 * 
 * @param {Client} client 
 * @param {Buffer} data 
 * @param {string} remote 
 */
export async function write(client, data, remote) {
  const exec = promisify(client.exec.bind(client));
  const stream = await exec(`scp -t ${remote}`);
  const basename = path.basename(remote);
  const info = `C0644 ${data.length} ${basename}\n`;

  const { stdin } = stream;

  stdin.write(info);
  stdin.write(data);
  stdin.write('\x00');
}

/**
 * 
 * @param {Client} client 
 * @param {string} local 
 * @param {string} remote 
 */
export async function upload(client, local, remote) {
  const exec = promisify(client.exec.bind(client));
  const stream = await exec(`scp -t ${remote}`);

  const { mode, size } = await fsp.stat(local);
  const oct = (mode & 0o777).toString(8);
  const basename = path.basename(remote);
  const info = `C0${oct} ${size} ${basename}\n`;
  stream.stdin.write(info);

  await new Promise((resolve, reject) => {
    createReadStream(local)
      .once('end', resolve)
      .once('error', reject)
      .pipe(stream.stdin);
  });

  stream.stdin.write('\x00');
}

const State = {
  INIT: 0,
  META: 1,
  DATA: 2,
  SINK: 3,
  DONE: 4
}

class SCPReceiver extends Duplex {
  /**
   * @private
   */
  state = State.INIT;
  /**
   * @private
   */
  remain = 0;

  /**
   * @type {string[]}
   * @private
   */
  components = [];

  /**
   * @type {Buffer[]}
   * @private
   */
  trunks = [];

  /**
   * @type {WriteStream | null}
   * @private
   */
  output = null;

  /**
   * @type {Date | null}
   * @private
   */
  mtime = null;

  /**
   * @type {Date | null}
   * @private
   */
  atime = null;

  /**
   * @type {string | null}
   */
  current = null;

  #dest;
  #recursive;

  /**
   * 
   * @param {string} dest 
   * @param {boolean} recursive 
   */
  constructor(dest, recursive) {
    super();
    this.#dest = dest;
    this.#recursive = recursive;
    this.components = [dest];
  }

  /**
   * 
   * @param {string} basename 
   * @returns 
   */
  #path(basename) {
    if (basename.includes('/')) throw new Error('Invalid path');
    return path.join(...this.components, basename);
  }

  #ack() {
    this.push(Buffer.from([0]));
  }

  /**
   * 
   * @param {string} name
   */
  #pushd(name) {
    this.components.push(name);
  }

  #popd() {
    this.components.pop();
  }

  _read() {
    if (this.state == State.INIT) {
      this.#ack();
      this.state = State.META;
    }
  }

  /**
   * 
   * @param {Buffer} buf 
   * @returns 
   */
  async #meta(buf) {
    const line = buf.toString();

    if (line == 'E') { // sink
      this.state = State.META;
      this.#popd();
      return;
    }

    if (line.startsWith('T')) { // time
      const values = line.substring(1).split(' ').map(str => parseInt(str, 10));
      if (values.length !== 4)
        throw new Error(`Protocol Error, response: ${line}`);

      const [mtime, mtimeNsec, atime, atimeNsec] = values;
      if (mtimeNsec > 999999 || atimeNsec > 999999)
        throw new Error(`time out of range: ${line}`);

      this.mtime = new Date(mtime * 1000 + mtimeNsec / 1000000);
      this.atime = new Date(atime * 1000 + atimeNsec / 1000000);
      return;
    }

    const isFile = line.startsWith('C');
    const isDir = line.startsWith('D');

    if (!isFile && !isDir) {
      throw new Error(`Protocol Error, response: ${line}`);
    }

    const [strMode, strSize, basename] = line.split(' ');
    const mode = parseInt(strMode.slice(1), 8);
    const size = parseInt(strSize, 10);
    if (basename.includes('/')) throw new Error('Invalid path');

    const name = basename.trimEnd();
    const dest = this.#recursive ? this.#path(name) : this.#dest;

    if (isFile) {
      this.state = State.DATA;
      this.output = createWriteStream(dest, { mode });
      this.current = dest;
      this.remain = size;
    } else if (isDir) {
      await fsp.mkdir(dest, { recursive: true });
      if (this.atime && this.mtime) {
        await fsp.utimes(dest, this.atime, this.mtime);
      }
      this.#pushd(name);
    }
  }

  /**
   * 
   * @param {Buffer} chunk 
   * @param {BufferEncoding} encoding 
   * @param {function} callback 
   */
  _write(chunk, encoding, callback) {
    if (this.state == State.META) {
      const index = chunk.indexOf(0x0A);
      if (index > -1) {
        this.trunks.push(chunk.slice(0, index));
        const meta = Buffer.concat(this.trunks);
        this.trunks = [chunk.slice(index + 1)];
        this.#meta(meta);
        this.#ack();
      } else {
        this.trunks.push(chunk);
      }
    } else if (this.state == State.DATA) {
      if (!this.output) throw new Error('Invalid state');
      if (chunk.length > this.remain) {
        this.output.end(chunk.slice(0, this.remain));
        this.state = State.META;
        if (chunk[this.remain] !== 0) throw new Error('Protocol Error');
        this.trunks = [chunk.slice(this.remain + 1)];
        this.#ack();
        this.remain = 0;

        // update time
        if (this.current && this.mtime && this.atime) {
          fsp.utimes(this.current, this.atime, this.mtime);
          this.current = null;
        }
      } else {
        this.output.write(chunk);
        this.remain -= chunk.length;
      }
    } else {
      throw new Error('Invalid state');
    }

    callback();
  }
}

/**
 * 
 * @param {Client} client 
 * @param {string} remote 
 * @param {string} local 
 * @param {recursive} recursive 
 */
export async function download(client, remote, local, recursive = false) {
  const exec = promisify(client.exec.bind(client));
  const stream = await exec(`scp -v -f -p ${recursive ? '-r' : ''} ${remote}`);

  // stream.stdout.pipe(process.stdout);

  const duplex = new SCPReceiver(local || '.', recursive);
  stream.stdout.pipe(duplex);
  duplex.pipe(stream.stdin);

  await new Promise((resolve, reject) => {
    duplex
      .on('finish', resolve)
      .on('error', reject);
  });
}

/**
 * 
 * @param {Client} client 
 * @param {string} [initialCommand]
 * @returns 
 */
export async function interactive(client, initialCommand) {
  const { stdin, stdout, stderr } = process;
  const { isTTY } = stdout;

  return new Promise((resolve, reject) => {
    client.shell({ term: process.env.TERM || 'vt100' }, (err, stream) => {
      if (err) {
        return reject(err);
      }

      if (isTTY && stdin.setRawMode) {
        stdin.setRawMode(true);
      }

      stream.pipe(stdout);
      stream.stderr.pipe(stderr);
      stdin.pipe(stream);

      if (initialCommand) stream.write(initialCommand + '\n');

      const onResize = () => {
        const [w, h] = process.stdout.getWindowSize();
        stream.setWindow(`${stdout.rows}`, `${stdout.columns}`, `${w}`, `${h}`)
      };

      const cleanup = () => {
        if (isTTY) {
          stdout.removeListener('resize', onResize);
          if (stdin.setRawMode) stdin.setRawMode(false);
        }

        stream.unpipe();
        stream.stderr.unpipe();
        stdin.unpipe();
      }

      const onError = (err) => {
        cleanup();
        reject(err);
      }

      if (isTTY) {
        stream.once('data', onResize);
        process.stdout.on('resize', onResize);
      }

      client.once('end', () => onError(new Error('Connection closed')));

      stream.on('error', onError).on('end', () => {
        resolve();
        cleanup();
      })
    });
  });
}