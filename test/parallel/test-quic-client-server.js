'use strict';

// Tests a simple QUIC client/server round-trip

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const { Buffer } = require('buffer');
const Countdown = require('../common/countdown');
const assert = require('assert');
const fs = require('fs');
const fixtures = require('../common/fixtures');
const key = fixtures.readKey('agent8-key.pem', 'binary');
const cert = fixtures.readKey('agent8-cert.pem', 'binary');

const createSocket = require('quic');

let client;
const server = createSocket({ type: 'udp4', port: 0 });

const unidata = ['I wonder if it worked.', 'test'];
const kServerName = 'test';
const kALPN = 'h3-20';

const countdown = new Countdown(2, () => {
  server.close();
  client.close();
});

server.listen({ key, cert });
server.on('session', common.mustCall((session) => {
  session.on('secure', common.mustCall((servername, alpn) => {
    assert.strictEqual(session.servername, servername);
    assert.strictEqual(servername, kServerName);
    assert.strictEqual(session.alpnProtocol, alpn);
    const uni = session.openStream({ halfOpen: true });
    uni.write(unidata[0]);
    uni.end(unidata[1]);
  }));

  session.on('stream', common.mustCall((stream) => {
    const file = fs.createReadStream(__filename);
    file.pipe(stream);
    stream.setEncoding('utf8');
    stream.resume();
    stream.on('end', common.mustCall());
  }));
}));

server.on('ready', common.mustCall(() => {
  client = createSocket({ type: 'udp4', port: 0 });
  const req = client.connect({
    type: 'udp4',
    address: 'localhost',
    port: server.address.port,
    rejectUnauthorized: false,
    maxStreamsUni: 1000,
    servername: kServerName
  });

  assert.strictEqual(req.servername, kServerName);

  req.on('sessionTicket', common.mustCall((id, ticket, params) => {
    assert(id instanceof Buffer);
    assert(ticket instanceof Buffer);
    assert(params instanceof Buffer);
  }, 2));

  req.on('secure', common.mustCall((servername, alpn) => {
    assert.strictEqual(servername, kServerName);
    assert.strictEqual(req.servername, kServerName);
    assert.strictEqual(alpn, kALPN);
    assert.strictEqual(req.alpnProtocol, kALPN);
    assert(req.ephemeralKeyInfo);
    assert(req.getPeerCertificate());

    const file = fs.createReadStream(__filename);
    const stream = req.openStream();
    file.pipe(stream);
    stream.resume();
    stream.on('close', common.mustCall(() => countdown.dec()));
  }));

  req.on('stream', common.mustCall((stream) => {
    let data = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => data += chunk);
    stream.on('end', common.mustCall(() => {
      assert.strictEqual(data, unidata.join(''));
    }));
    stream.on('close', common.mustCall(() => countdown.dec()));
  }));

}));

server.on('listening', common.mustCall());
