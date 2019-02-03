'use strict';

const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

const createSocket = require('quic');

const socket = createSocket({ type: 'udp4', port: 1234 });

socket.listen({});

//socket.close();
socket.on('ready', common.mustCall(() => {
  console.log(socket.address);
}));

socket.on('listening', common.mustCall());
