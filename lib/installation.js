import { Duplex } from 'stream';

import BPlistCreator from 'bplist-creator';
import BPlistParser from 'bplist-parser';

const STATE = {
  GET_LENGTH: 0,
  READ_BODY: 1,
};

/**
 * @typedef App
 * @prop {string} CFBundleVersion
 * @prop {string} CFBundleIdentifier
 * @prop {number} CFBundleDisplayName
 * @prop {string} CFBundleExecutable
 * @prop {string} CFBundleName
 * @prop {string} CFBundleShortVersionString
 * @prop {string} Path
 * @prop {string} Container
 *
 */

/**
 * @typedef Response
 * @prop {'BrowsingApplications' | 'Complete'} Status
 * @prop {App[]} CurrentList
 * @prop {number} CurrentIndex
 * @prop {number} CurrentAmount
 *
 */

class PacketWrapper extends Duplex {
  sum = 0;
  buffer = Buffer.alloc(0);

  /**
   * @private
   * @type {STATE}
   */
  state = STATE.GET_LENGTH;
  expected = 4;

  /**
   *
   * @param {Buffer} chunk
   * @param {BufferEncoding} encoding
   * @param {function} callback
   */
  _write(chunk, encoding, callback) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= this.expected) {
      this.digest();
    }

    callback();
  }

  digest() {
    if (this.state == STATE.GET_LENGTH) {
      this.expected = this.buffer.readUInt32BE();
      this.state = STATE.READ_BODY;
      this.buffer = this.buffer.slice(4);
    } else {
      const tail = this.buffer.slice(this.expected);
      this.emit('response', this.buffer.slice(0, this.expected));
      this.expected = 4;
      this.state = STATE.GET_LENGTH;
      this.buffer = tail;
    }
  }

  /**
   *
   * @param {Buffer} packet
   */
  send(packet) {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(packet.length);
    this.push(header);
    this.push(packet);
  }

  _read() {}
}

/**
 *
 * @param {import("frida").Device} dev
 * @returns {Promise<App[]>}
 */
export async function apps(dev) {
  const remote = await dev.openChannel(
    `lockdown:com.apple.mobile.installation_proxy`
  );

  const wrapper = new PacketWrapper();
  remote.pipe(wrapper);
  wrapper.pipe(remote);

  const msg = BPlistCreator({
    Command: 'Browse',
    ClientOptions: {
      ApplicationType: 'Any',
      ReturnAttributes: [
        'CFBundleDisplayName',
        'CFBundleExecutable',
        'CFBundleIdentifier',
        'CFBundleName',
        'CFBundleVersion',
        'CFBundleShortVersionString',
        'Path',
        'Container',
      ],
    },
  });

  return new Promise((resolve) => {
    /** @type {App[]} */
    const allApps = [];
    wrapper.on('response', (msg) => {
      const parsed = BPlistParser.parseBuffer(msg);
      const result = parsed[0];

      if (result.Status == 'Complete') {
        resolve(allApps);
        remote.destroy();
      } else if (result.Status == 'BrowsingApplications') {
        allApps.push(...result.CurrentList);
      }
    });
    wrapper.send(msg);
  });
}
