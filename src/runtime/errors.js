'use strict';

const { ERROR_CODES } = require('./protocol');

class RuntimeAgentError extends Error {
  constructor(message, code = ERROR_CODES.OPERATION_FAILED) {
    super(message);
    this.name = 'RuntimeAgentError';
    this.code = code;
  }
}

// Thrown by the client whenever it cannot reach, authenticate with, or agree
// on a protocol version with the agent. Call sites already catch/log/report
// generic Errors, so callers do not need new error-handling shape — only a
// consistent, user-facing message.
class RuntimeAgentUnavailableError extends RuntimeAgentError {
  constructor(reason = 'runtime agent disconnected') {
    super(`Docker runtime unavailable: ${reason}.`, ERROR_CODES.DOCKER_UNAVAILABLE);
    this.name = 'RuntimeAgentUnavailableError';
  }
}

module.exports = { RuntimeAgentError, RuntimeAgentUnavailableError };
