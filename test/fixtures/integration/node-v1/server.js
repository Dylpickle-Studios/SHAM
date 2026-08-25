'use strict';

const http = require('node:http');
const version = process.env.SHAM_TEST_VERSION || 'SHAM_TEST_VERSION_1';

http.createServer((req, res) => {
  console.log(`fixture ${version} ${req.method} ${req.url}`);
  if (req.url === '/health') return res.writeHead(200).end('healthy');
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end(version);
}).listen(Number(process.env.PORT || 3000), '127.0.0.1');
