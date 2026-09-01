const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const temporaryData = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-upload-folder-config-'));
process.env.SHAM_DATA_PATH = temporaryData;
process.env.SHAM_JWT_SECRET = 'upload-folder-test-secret-at-least-32-characters';
test.after(() => fs.rmSync(temporaryData, { recursive: true, force: true }));

const { installUpload, installUploadAsync } = require('../src/upload-utils');
const { readManifest, manifestOverrides } = require('../src/runtime-spec');

function file(name, content) {
  const buffer = Buffer.from(content);
  return { originalname: name, size: buffer.length, buffer };
}

test('folder upload strips one common enclosing directory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-upload-'));
  const destination = path.join(root, 'site');
  try {
    installUpload({
      archive: null,
      files: [file('index.html', '<h1>Hello</h1>'), file('app.js', 'console.log(1)')],
      relativePaths: ['website/index.html', 'website/assets/app.js'],
      destination,
      entryFile: 'index.html',
      maxBytes: 1024 * 1024
    });
    assert.equal(fs.readFileSync(path.join(destination, 'index.html'), 'utf8'), '<h1>Hello</h1>');
    assert.equal(fs.readFileSync(path.join(destination, 'assets/app.js'), 'utf8'), 'console.log(1)');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('manifest preview staging accepts an upload without requiring an entry file', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-upload-preview-'));
  const destination = path.join(root, 'preview');
  try {
    installUpload({
      archive: null,
      files: [file('sham.yml', 'runtime:\n  driver: process\n  command: node server.js\nbuild:\n  install: npm ci\n'), file('server.js', 'process.exit(0)')],
      relativePaths: ['project/sham.yml', 'project/server.js'],
      destination,
      entryFile: '',
      maxBytes: 1024 * 1024
    });
    const record = readManifest(destination);
    assert.equal(record.filename, 'sham.yml');
    const config = manifestOverrides(record);
    assert.equal(config.driver, 'process');
    assert.equal(config.command, 'node server.js');
    assert.equal(config.installCommand, 'npm ci');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test('folder upload supports disk-backed temporary files', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-upload-'));
  const destination = path.join(root, 'site');
  const temporaryFile = path.join(root, 'temporary-upload');
  try {
    fs.writeFileSync(temporaryFile, '<h1>Disk backed</h1>');
    installUpload({
      archive: null,
      files: [{ originalname: 'index.html', size: fs.statSync(temporaryFile).size, path: temporaryFile }],
      relativePaths: ['index.html'],
      destination,
      entryFile: 'index.html',
      maxBytes: 1024 * 1024
    });
    assert.equal(fs.readFileSync(path.join(destination, 'index.html'), 'utf8'), '<h1>Disk backed</h1>');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});


test('async upload installation runs disk work outside the request thread', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-upload-'));
  const destination = path.join(root, 'site');
  const temporaryFile = path.join(root, 'temporary-upload');
  try {
    fs.writeFileSync(temporaryFile, '<h1>Worker</h1>');
    await installUploadAsync({
      archive: null,
      files: [{ originalname: 'index.html', size: fs.statSync(temporaryFile).size, path: temporaryFile }],
      relativePaths: ['index.html'],
      destination,
      entryFile: 'index.html',
      maxBytes: 1024 * 1024
    });
    assert.equal(fs.readFileSync(path.join(destination, 'index.html'), 'utf8'), '<h1>Worker</h1>');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('failed replacement preserves the existing website', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sham-upload-'));
  const destination = path.join(root, 'site');
  try {
    installUpload({
      archive: null,
      files: [file('index.html', 'old')],
      relativePaths: ['index.html'],
      destination,
      entryFile: 'index.html',
      maxBytes: 1024 * 1024
    });
    assert.throws(() => installUpload({
      archive: null,
      files: [file('other.html', 'new')],
      relativePaths: ['other.html'],
      destination,
      entryFile: 'index.html',
      maxBytes: 1024 * 1024
    }));
    assert.equal(fs.readFileSync(path.join(destination, 'index.html'), 'utf8'), 'old');
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
