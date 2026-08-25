const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Transform, pipeline } = require('node:stream');

class CappedDiskStorage {
  constructor(directory, maxBytes) {
    this.directory = directory;
    this.maxBytes = maxBytes;
    fs.mkdirSync(directory, { recursive: true });
  }

  _handleFile(req, file, callback) {
    const temporaryPath = path.join(this.directory, `upload-${crypto.randomUUID()}`);
    const output = fs.createWriteStream(temporaryPath, { flags: 'wx', mode: 0o600 });
    let fileBytes = 0;
    const counter = new Transform({
      transform: (chunk, _encoding, done) => {
        fileBytes += chunk.length;
        req.shamUploadBytes = (req.shamUploadBytes || 0) + chunk.length;
        if (fileBytes > this.maxBytes || req.shamUploadBytes > this.maxBytes) {
          const error = /** @type {NodeJS.ErrnoException} */ (new Error('Upload exceeds the configured size limit.'));
          error.code = 'LIMIT_FILE_SIZE';
          done(error);
          return;
        }
        done(null, chunk);
      }
    });

    pipeline(file.stream, counter, output, (error) => {
      if (error) {
        fs.rm(temporaryPath, { force: true }, () => callback(error));
        return;
      }
      callback(null, { path: temporaryPath, size: fileBytes });
    });
  }

  _removeFile(_req, file, callback) {
    const temporaryPath = file.path;
    delete file.path;
    fs.rm(temporaryPath, { force: true }, callback);
  }
}

function uploadedFiles(req) {
  const files = [];
  if (req.file) files.push(req.file);
  if (Array.isArray(req.files)) files.push(...req.files);
  else if (req.files && typeof req.files === 'object') {
    for (const values of Object.values(req.files)) if (Array.isArray(values)) files.push(...values);
  }
  return files;
}

function cleanupUploadedFiles(req) {
  for (const file of uploadedFiles(req)) {
    if (file?.path) fs.rm(file.path, { force: true }, () => {});
  }
}

module.exports = { CappedDiskStorage, cleanupUploadedFiles };
