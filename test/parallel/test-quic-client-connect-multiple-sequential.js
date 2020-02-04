// Flags: --no-warnings
'use strict';
const common = require('../common');
if (!common.hasQuic)
  common.skip('missing quic');

// Test that .connect() can be called multiple times with different servers.

const quic = require('quic');

const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent1-key.pem', 'binary');
const cert = fixtures.readKey('agent1-cert.pem', 'binary');
const ca = fixtures.readKey('ca1-cert.pem', 'binary');

const { once } = require('events');

(async function() {
  const servers = [];
  for (let i = 0; i < 3; i++) {
    const server = quic.createSocket();

    server.listen({ key, cert, ca, alpn: 'meow' });

    server.on('session', common.mustCall((session) => {
      session.on('secure', common.mustCall(() => {
        const stream = session.openStream({ halfOpen: true });
        stream.end('Hi!');
      }));
    }));

    server.on('close', common.mustCall());

    servers.push(server);
  }

  await Promise.all(servers.map((server) => once(server, 'ready')));

  const client = quic.createSocket({ client: { key, cert, ca, alpn: 'meow' } });

  const reqs = [];
  for (const server of servers) {
    const req = client.connect({
      address: 'localhost',
      port: server.endpoints[0].address.port
    });

    req.on('stream', common.mustCall((stream) => {
      stream.resume();
      stream.on('close', common.mustCall(() => {
        req.close();
      }));
    }));
    reqs.push(once(req, 'close'));
  }
  await Promise.all(reqs);

  client.close();

  await once(client, 'close');
  for (const server of servers)
    server.close();

  await Promise.all(servers.map((server) => once(server, 'close')));
})().then(common.mustCall());
