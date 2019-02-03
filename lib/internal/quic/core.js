'use strict';

const EventEmitter = require('events');
const { Duplex } = require('stream');
const {
  defaultTriggerAsyncIdScope,
  symbols: {
    async_id_symbol,
    owner_symbol,
  },
} = require('internal/async_hooks');
const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_CALLBACK
  }
} = require('internal/errors');
const {
  QuicSocket: QuicSocketHandle,
  setCallbacks,
  socketBind,
  socketClose
} = internalBinding('quic');

const kHandle = Symbol('handle');

// Called when the socket is ready for use
function onSocketReady(socketHandle) {
  const socket = socketHandle[owner_symbol];
}

// Called when the socket is closed
function onSocketClose(socketHandle) {
  const socket = socketHandle[owner_symbol];
}

// Called when an error occurs on the socket
function onSocketError(socketHandle, error) {
  const socket = socketHandle[owner_symbol];
  socket.destroy(error);
}

// Called when a new QuicSession is ready to use
function onSessionReady(sessionHandle) {
  const session = sessionHandle[owner_symbol];
}

// Called when a QuicSession is closed
function onSessionClose(sessionHandle) {
  const session = sessionHandle[owner_symbol];
}

// Called when an error occurs in a QuicSession
function onSessionError(sessionHandle, error) {
  const session = sessionHandle[owner_symbol];
  session.destroy(error);
}

// Called when a new QuicStream is ready to use
function onStreamReady(streamHandle) {
  const stream = streamHandle[owner_symbol];
}

// Called when a stream is closed
function onStreamClose(streamHandle) {
  const stream = streamHandle[owner_symbol];
}

// Called when an error occurs in a QuicStream
function onStreamError(streamHandle, error) {
  const stream = streamHandle[owner_symbol];
  stream.destroy(error);
}

// Register the callbacks with the QUIC internal binding.
setCallbacks({
  onSocketReady,
  onSocketClose,
  onSocketError,
  onSessionReady,
  onSessionClose,
  onSessionError,
  onStreamReady,
  onStreamClose,
  onStreamError
});

class QuicSocket extends EventEmitter {

  // Events:
  // * session -- emitted when a new server session is established
  // * ready -- emitted when the socket is ready for use
  // * close -- emitted when the socket is closed (after any associated sessions
  //            are closed)
  // * error -- emitted when an error occurs

  constructor(options) {
    super();
    const handle = this[kHandle] = new QuicSocketHandle(options);
    handle[owner_symbol] = this;
  }

  // Initializes this QuicSocket as a server using the specified options.
  listen(options, callback) {
    // TODO(jasnell): Bind the server to the port/address. Invoke the callback
    // when ready.
    // TODO(jasnell): Obviously we need to pass options in to the bind call
    socketBind(this[kHandle]);
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('ready', callback);
    }
  }

  // Creates a QuicClientSession
  connect(options) {
    // TODO(jasnell): A single client will track it's open sessions. Connect
    // will either create a new session or return a reference to an existing
    // one, based on a number of factors. For now, always create a new session.
    return new QuicClientSession(options);
  }

  close(callback) {
    // TODO(jasnell): Gracefully close the socket, all associated sessions, and
    // streams. New sessions will be rejected. Requests to open new streams will
    // be rejected.
    socketClose(this[kHandle]);
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }
  }

  destroy(error) {
    // TODO(jasnell): Immediately destroy the socket, all associated sessions,
    // and streams. If error is specified, an error event will be emitted on
    // the server, sessions, and streams.
  }

  ref() {}

  unref() {}

  get address() {}

  get listening() {}
}

class QuicSession extends EventEmitter {
  // Events:
  // * stream -- New Stream was Created
  // * error -- Error occurred
  // * ready -- Session is ready for use
  // * close -- Server is closed
  constructor() {
    super();
  }

  openStream(options) {}

  close(callback) {
    // TODO(jasnell): Gracefully close the session and all associated streams.
    // No new streams can be created or will be accepted.
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }
  }

  destroy(error) {}
}

class QuicServerSession extends QuicSession {
  constructor(server) {
    super();
  }
}

class QuicClientSession extends QuicSession {
  constructor(client) {
    super();
  }
}

class QuicStream extends Duplex {
  constructor(options) {
    super(options);
  }
}

function createSocket(options = {}) {
  if (options == null || typeof options !== 'object')
    throw new ERR_INVALID_ARG_TYPE('options', 'Object', options);
  return new QuicSocket(options);
}

module.exports = {
  createSocket
};
