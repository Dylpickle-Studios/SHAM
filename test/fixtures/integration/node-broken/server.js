'use strict';

// Deliberately never opens its configured port. SHAM must reject this release
// during readiness and keep the previous active gateway serving traffic.
setInterval(() => console.log('fixture SHAM_TEST_BROKEN waiting'), 1000);
