import { stat } from 'fs/promises';

export const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export const directoryExists = path => stat(path)
  .then(info => info.isDirectory())
  .catch(() => false);
