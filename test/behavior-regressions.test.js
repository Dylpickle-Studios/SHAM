'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { ShamHarness } = require('./integration/harness');

function rawRequest(baseUrl, body) {
  const url = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: url.hostname,
      port: url.port,
      path: '/api/auth/login',
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    request.once('error', reject);
    request.end(body);
  });
}

test('malformed JSON receives a controlled client error from a real SHAM instance', async () => {
  const sham = await new ShamHarness().start({ register: false });
  try {
    const response = await rawRequest(sham.baseUrl, '{"username":');
    assert.equal(response.status, 400);
    assert.match(response.body, /invalid JSON/i);
  } finally {
    await sham.close();
  }
});
