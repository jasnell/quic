'use strict';

// Common bits for all QUIC-related tests

const { debuglog } = require('util');
const fixtures = require('./fixtures');
const kHttp3Alpn = 'h3-25';

const [ key, cert, ca ] =
  fixtures.readKeys(
    'binary',
    'agent1-key.pem',
    'agent1-cert.pem',
    'ca1-cert.pem');

const debug = debuglog('test');

const kServerPort = process.env.NODE_DEBUG_KEYLOG ? 5678 : 0;
const kClientPort = process.env.NODE_DEBUG_KEYLOG ? 5679 : 0;

function setupKeylog(session) {
  if (process.env.NODE_DEBUG_KEYLOG) {
    const kl = fs.createWriteStream(process.env.NODE_DEBUG_KEYLOG);
    session.on('keylog', kl.write.bind(kl));
  }
}

module.exports = {
  key,
  cert,
  ca,
  debug,
  kServerPort,
  kClientPort,
  setupKeylog,
  kHttp3Alpn,
};
