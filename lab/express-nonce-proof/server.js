'use strict';

const express = require('express');

const proofToken = process.env.N2S_PROOF;
if (!/^[0-9a-f]{32}$/.test(proofToken || '')) {
  throw new Error('N2S_PROOF must be a fresh 128-bit lowercase hex token');
}

const app = express();
app.get('/health', (_request, response) => response.end(`PONG ${proofToken}\n`));
app.post('/upload', express.json(), (_request, response) => response.end('DONE\n'));
app.use((error, _request, response, _next) => {
  response.status(400).end(`ERR ${error.code || error.type || error.message}\n`);
});
app.listen(3000, '0.0.0.0');
