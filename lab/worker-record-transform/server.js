'use strict';

const net = require('node:net');
const zlib = require('node:zlib');
const { Worker, isMainThread, parentPort, workerData } = require('node:worker_threads');

const MAX_FRAME = 32 * 1024 * 1024;
const BROTLI_CHUNK_SIZE = 0x330;
const RECORD_SIZE = Number.parseInt(process.env.N2S_RECORD_SIZE || '0x330', 0);
const LEAK_RECORD_SIZE = Number.parseInt(process.env.N2S_LEAK_RECORD_SIZE || '0', 0);
const LEAK_PORT = Number.parseInt(process.env.N2S_LEAK_PORT || '3001', 10);
const SERVER_PROFILE = process.env.N2S_SERVER_PROFILE || 'baseline';
const HEAP_NOISE_BLOCKS = Number.parseInt(process.env.N2S_HEAP_NOISE_BLOCKS || '0', 10);
const SERVER_PROFILES = new Set(['baseline', 'observed', 'socket-tuned']);

if (!Number.isSafeInteger(RECORD_SIZE) || RECORD_SIZE < 0x100 || RECORD_SIZE > 0x400) {
  throw new Error('N2S_RECORD_SIZE is outside the isolated lab range');
}
if (LEAK_RECORD_SIZE !== 0 &&
    (!Number.isSafeInteger(LEAK_RECORD_SIZE) || LEAK_RECORD_SIZE < 0x100 || LEAK_RECORD_SIZE > 0x400)) {
  throw new Error('N2S_LEAK_RECORD_SIZE is outside the isolated lab range');
}
if (!Number.isSafeInteger(LEAK_PORT) || LEAK_PORT < 1024 || LEAK_PORT > 65535 || LEAK_PORT === 3000) {
  throw new Error('N2S_LEAK_PORT is outside the isolated lab range');
}
if (!SERVER_PROFILES.has(SERVER_PROFILE)) {
  throw new Error('N2S_SERVER_PROFILE is outside the isolated lab allowlist');
}
if (!Number.isSafeInteger(HEAP_NOISE_BLOCKS) || HEAP_NOISE_BLOCKS < 0 || HEAP_NOISE_BLOCKS > 32) {
  throw new Error('N2S_HEAP_NOISE_BLOCKS is outside the isolated lab range');
}

if (!isMainThread) {
  const recordSize = workerData?.recordSize ?? RECORD_SIZE;
  const preformatRecord = workerData?.preformatRecord === true;
  // Retained allocations model unrelated request state in the same worker.
  // They are bounded and deterministic so benchmark results remain comparable.
  const heapNoise = Array.from({ length: HEAP_NOISE_BLOCKS }, (_, index) => {
    const block = Buffer.allocUnsafeSlow(0x100 + ((index % 8) * 0x20));
    block.fill(index & 0xff);
    return block;
  });
  const decoder = zlib.createBrotliDecompress({ chunkSize: BROTLI_CHUNK_SIZE });
  let transform = false;

  decoder.on('data', (chunk) => {
    if (!transform) return;
    let timestamp;
    if (preformatRecord) timestamp = new Intl.DateTimeFormat('en-US').format(new Date());
    const record = Buffer.allocUnsafeSlow(recordSize);
    chunk.copy(record, 0, 0, Math.min(chunk.length, record.length));
    if (timestamp === undefined) timestamp = new Intl.DateTimeFormat('en-US').format(new Date());
    parentPort.postMessage({ data: record, timestamp, retainedNoiseBlocks: heapNoise.length });
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
  function createRecordServer(recordSize, preformatRecord = false) {
    const metrics = { accepted: 0, closed: 0, bytesOut: 0 };
    return net.createServer((socket) => {
      metrics.accepted += 1;
      if (SERVER_PROFILE === 'socket-tuned') {
        socket.setNoDelay(true);
        socket.setKeepAlive(true, 1000);
        socket.setTimeout(15000, () => socket.destroy());
      }
      const worker = new Worker(__filename, { workerData: { recordSize, preformatRecord } });
      let size;
      let busy = false;
      let first = true;

      worker.on('message', (message) => {
        if (message.data && !socket.writableEnded) {
          socket.write(message.data);
          if (SERVER_PROFILE === 'observed') metrics.bytesOut += message.data.length;
        }
        if (message.ack || message.done) {
          busy = false;
          if (message.ack && !socket.writableEnded) socket.write('ACK\n');
          readFrame();
        }
        if (message.end !== undefined && !socket.writableEnded) socket.end(message.end);
      });
      worker.on('error', () => socket.destroy());
      socket.on('error', () => {});
      socket.on('close', () => {
        metrics.closed += 1;
        worker.terminate();
      });

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
    });
  }
  const server = createRecordServer(RECORD_SIZE);
  server.maxConnections = 64;
  server.listen(3000, '127.0.0.1', () => {
    console.log('N2S_READY');
  });
  if (LEAK_RECORD_SIZE !== 0) {
    const leakServer = createRecordServer(LEAK_RECORD_SIZE, true);
    leakServer.maxConnections = 64;
    leakServer.listen(LEAK_PORT, '127.0.0.1', () => {
      console.log('N2S_LEAK_READY');
    });
  }
}
