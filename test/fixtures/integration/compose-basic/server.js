'use strict';
const http = require('node:http');
http.createServer((_req, res) => res.end('SHAM_TEST_COMPOSE_OK')).listen(3000, '0.0.0.0');
