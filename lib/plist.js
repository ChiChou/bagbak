import plist from 'plist';
import bPlistParser from 'bplist-parser';

/**
 * 
 * @param {Buffer} buffer
 * @returns {any}
 */
export function parse(buffer) {
  if (buffer.slice(0, 6).toString() === 'bplist') {
    return bPlistParser.parseBuffer(buffer)[0];
  } else if (buffer.slice(0, 6).toString() === '<?xml ') {
    return plist.parse(buffer.toString());
  } else {
    console.log(buffer.toString().slice(0, 6));
    throw Error('Unknown plist format');
  }
}
