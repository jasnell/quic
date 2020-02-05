// Flags: --no-warnings
'use strict';

const common = require('../common');
if (!common.hasQuic)
  common.skip('missing quic');

const assert = require('assert');
const { createSocket } = require('quic');
const { key, cert, ca } = require('../common/quic');

const kServerName = 'agent2';
const kALPN = 'zzz';
// Allow error for 500 milliseconds more.
const error = common.platformTimeout(500);
const idleTimeout = common.platformTimeout(1000);

// Test client idle timeout.
{
  let client;
  const server = createSocket();
  server.listen({ key, cert, ca, alpn: kALPN });

  server.on('session', common.mustCall());

  server.on('ready', common.mustCall(() => {
    client = createSocket({ client: { key, cert, ca, alpn: kALPN } });
    const start = Date.now();
    const clientSession = client.connect({
      address: 'localhost',
      port: server.endpoints[0].address.port,
      servername: kServerName,
      idleTimeout,
    });

    clientSession.on('close', common.mustCall(() => {
      client.close();
      server.close();
      assert(Date.now() - start < idleTimeout + error);
    }));
  }));
}

// Test server idle timeout.
{
  let client;
  let start;
  const server = createSocket();
  server.listen({ key, cert, ca, alpn: kALPN, idleTimeout });

  server.on('session', common.mustCall((serverSession) => {
    serverSession.on('close', common.mustCall(() => {
      client.close();
      server.close();
      assert(Date.now() - start < idleTimeout + error);
    }));
  }));

  server.on('ready', common.mustCall(() => {
    client = createSocket({ client: { key, cert, ca, alpn: kALPN } });
    start = Date.now();
    const clientSession = client.connect({
      address: 'localhost',
      port: server.endpoints[0].address.port,
      servername: kServerName,
    });

    clientSession.on('close', common.mustCall());
  }));
}
