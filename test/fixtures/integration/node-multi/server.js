'use strict';

const http = require('node:http');

function serve(port, body, label) {
  http.createServer((req, res) => {
    console.log(`fixture ${label} ${req.method} ${req.url}`);
    if (req.url === '/health') return res.writeHead(200).end('healthy');
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(body);
  }).listen(Number(port), '127.0.0.1');
}

serve(process.env.PORT || 3000, 'SHAM_MULTI_PUBLIC', 'public');
serve(process.env.ADMIN_PORT || 3001, 'SHAM_MULTI_PRIVATE_ADMIN', 'admin');
