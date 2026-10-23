'use strict';

const net = require('node:net');
const zlib = require('node:zlib');
const { Worker, isMainThread, parentPort } = require('node:worker_threads');

const MAX_FRAME = 32 * 1024 * 1024;
const BROTLI_CHUNK_SIZE = 0x330;
const RECORD_SIZE = Number.parseInt(process.env.N2S_RECORD_SIZE || '0x330', 0);

if (!Number.isSafeInteger(RECORD_SIZE) || RECORD_SIZE < 0x100 || RECORD_SIZE > 0x400) {
  throw new Error('N2S_RECORD_SIZE is outside the isolated lab range');
}

if (!isMainThread) {
  const decoder = zlib.createBrotliDecompress({ chunkSize: BROTLI_CHUNK_SIZE });
  let transform = false;

  decoder.on('data', (chunk) => {
    if (!transform) return;
    const record = Buffer.allocUnsafeSlow(RECORD_SIZE);
    chunk.copy(record, 0, 0, Math.min(chunk.length, record.length));
    const timestamp = new Intl.DateTimeFormat('en-US').format(new Date());
    parentPort.postMessage({ data: record, timestamp });
  });
  decoder.on('error', (error) => {
    parentPort.postMessage({ end: `ERR ${error.code || error.message}\n` });
  });
  parentPort.on('message', ({ first, body }) => {
    decoder.write(body, () => {
      if (first) {
        transform = true;
        parentPort.postMessage({ ack: true });
      } else {
        parentPort.postMessage({ done: true });
      }
    });
  });
} else {
  net.createServer((socket) => {
    const worker = new Worker(__filename);
    let size;
    let busy = false;
    let first = true;

    worker.on('message', (message) => {
      if (message.data && !socket.writableEnded) socket.write(message.data);
      if (message.ack || message.done) {
        busy = false;
        if (message.ack && !socket.writableEnded) socket.write('ACK\n');
        readFrame();
      }
      if (message.end !== undefined && !socket.writableEnded) socket.end(message.end);
    });
    worker.on('error', () => socket.destroy());
    socket.on('error', () => {});
    socket.on('close', () => worker.terminate());

    function readFrame() {
      if (busy) return;
      if (size === undefined) {
        const header = socket.read(4);
        if (header === null) return;
        size = header.readUInt32BE();
        if (size > MAX_FRAME) return socket.end('ERR PROTOCOL\n');
      }
      const body = size === 0 ? Buffer.alloc(0) : socket.read(size);
      if (body === null) return;
      size = undefined;
      if (body.length === 0) return socket.end('PONG\n');
      busy = true;
      worker.postMessage({ first, body });
      first = false;
    }

    socket.on('readable', readFrame);
  }).listen(3000, '127.0.0.1');
}
