'use strict';

const { debuglog } = require('util');
const debug = debuglog('quic');
const assert = require('assert');
const EventEmitter = require('events');
const { Duplex } = require('stream');
const {
  createSecureContext: _createSecureContext
} = require('tls');
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
    ERR_INVALID_ARG_VALUE,
    ERR_INVALID_CALLBACK,
    ERR_QUICSESSION_DESTROYED,
    ERR_QUICSOCKET_CLOSING,
    ERR_QUICSOCKET_DESTROYED,
    ERR_QUICSOCKET_LISTENING,
    ERR_QUICSOCKET_UNBOUND,
    ERR_QUIC_TLS13_REQUIRED
  },
  errnoException,
  exceptionWithHostPort
} = require('internal/errors');

const {
  QuicSocket: QuicSocketHandle,
  setCallbacks,
  constants: {
    AF_INET,
    AF_INET6,
    UV_EBADF,
    UV_UDP_IPV6ONLY,
    UV_UDP_REUSEADDR
  }
} = internalBinding('quic');

const emit = EventEmitter.prototype.emit;

// Lazy load dns
let dns;

const kHandle = Symbol('handle');
const kState = Symbol('state');
const kMaybeBind = Symbol('maybe-bind');
const kMaybeClose = Symbol('maybe-close');
const kReceiveStart = Symbol('receive-start');
const kReceiveStop = Symbol('receive-stop');
const kReady = Symbol('ready');

const kSocketUnbound = 0;
const kSocketPending = 1;
const kSocketBound = 2;
const kSocketClosing = 3;
const kSocketDestroyed = 4;

function lazyDNS() {
  if (!dns)
    dns = require('dns');
  return dns;
}

// Called when the socket has been bound and is ready for use
function onSocketReady(fd) {
  const socket = this[owner_symbol];
  assert(socket,
         'QuicSocket is undefined. Please report this as a bug in Node.js');
  socket[kReady](fd);
}

// Called when the socket is closed
function onSocketClose() {
  const socket = this[owner_symbol];
  assert(socket,
         'QuicSocket is undefined. Please report this as a bug in Node.js');
  // Destroy the socket without any error to shut it down
  socket.destroy();
}

// Called when an error occurs on the socket
function onSocketError(err) {
  const socket = this[owner_symbol];
  assert(socket,
         'QuicSocket is undefined. Please report this as a bug in Node.js');
  socket.destroy(errnoException(err));
}

// Called when a new QuicSession is ready to use
function onSessionReady(socketHandle, sessionHandle) {
  debug('A new QUIC server session has been created');
  const socket = socketHandle[owner_symbol];
  const session = new QuicServerSession(socket, sessionHandle);
  process.nextTick(emit.bind(socket, 'session', session));
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

function getSocketType(type) {
  switch (type) {
    case 'udp4': return AF_INET;
    case 'udp6': return AF_INET6;
  }
  throw new ERR_INVALID_ARG_VALUE('options.type', type);
}

function validateBindOptions(port, address) {
  if (port != null && typeof port !== 'number')
    throw new ERR_INVALID_ARG_TYPE('options.port', 'number', port);
  if (address != null && typeof address !== 'string')
    throw new ERR_INVALID_ARG_TYPE('options.address', 'string', address);
}

function lookup4(address, callback) {
  const { lookup } = lazyDNS();
  debug(`QuicSocket::bind::lookup4[${address}]`);
  lookup(address || '127.0.0.1', 4, callback);
}

function lookup6(address, callback) {
  const { lookup } = lazyDNS();
  debug(`QuicSocket::bind::lookup6[${address}]`);
  lookup(address || '::1', 6, callback);
}

// err is the fourth argument here because we are calling a bound
// copy of afterLookup where the type and port arguments
// are pre-set.
function afterLookup(type, port, err, ip) {
  debug(`QuicSocket::bind::afterLookup[${port}, ${ip}]`);
  if (err) {
    this.destroy(err);
    return;
  }
  // TODO(@jasnell): Check if the handle is still valid. Socket destroyed?
  // or Closing?
  let flags = 0;
  if (this[kState].reuseAddr)
    flags |= UV_UDP_REUSEADDR;
  if (this[kState].ipv6Only)
    flags |= UV_UDP_IPV6ONLY;

  const ret = this[kHandle].bind(type, ip, port || 0, flags);
  // TODO(@jasnell): QUIC specific error below
  if (ret) {
    debug(`QuicSocket::bind::afterLookup[error: ${ret}]`);
    this.destroy(exceptionWithHostPort(ret, 'bind', ip, port || 0));
  }
}

// QuicSocket wraps a UDP socket plus the associated TLS context and QUIC
// Protocol state. There may be *multiple* QUIC connections (QuicSession)
// associated with a single QuicSocket.
class QuicSocket extends EventEmitter {

  // Events:
  // * session -- emitted when a new server session is established
  // * ready -- emitted when the socket is ready for use
  // * close -- emitted when the socket is closed (after any associated sessions
  //            are closed)
  // * error -- emitted when an error occurs

  constructor(options = { type: 'udp4' }) {
    const {
      lookup,
      type = 'udp4',
      port = 0,
      address,
      ipv6Only = false,
      reuseAddr = false
    } = options || {};
    if (typeof type !== 'string')
      throw new ERR_INVALID_ARG_TYPE('options.type', 'string', type);
    if (lookup && typeof lookup !== 'function')
      throw new ERR_INVALID_ARG_TYPE('options.lookup', 'Function', lookup);
    validateBindOptions(port, address);
    debug(`QuicSocket::constructor[${type} ${port} ${address}]`);
    super();
    const typeVal = getSocketType(type);
    const handle = this[kHandle] = new QuicSocketHandle({ type: typeVal });
    handle[owner_symbol] = this;
    this[async_id_symbol] = handle.getAsyncId();
    this[kState] = {
      fd: UV_EBADF,
      port,
      address: address || (typeVal === AF_INET6 ? '::' : '0.0.0.0'),
      reuseAddr: !!reuseAddr,
      ipv6Only: !!ipv6Only,
      destroyed: false,
      state: kSocketUnbound,
      type: typeVal,
      lookup: lookup || (typeVal === AF_INET6 ? lookup6 : lookup4),
      serverListening: false,
      serverSecureContext: undefined,
      sessions: new Set()
    };
  }

  // Bind the UDP socket on demand, only if it hasn't already been bound.
  // Function is a non-op if the socket is already bound
  [kMaybeBind]() {
    const {
      state,
      type,
      lookup,
      port,
      address,
    } = this[kState];
    debug(`QuicSocket::kMaybeBind[${state}]`);
    if (state !== kSocketUnbound)
      return;

    // This socket will be in a pending state until it is bound. Once bound,
    // the this[kReady]() method will be called, switching the state to
    // kSocketBound and notifying the associated sessions
    this[kState].state = kSocketPending;
    const doAfterLookup = afterLookup.bind(this, type, port);
    lookup(address, doAfterLookup);
  }

  // Close is a graceful shutdown...a QuicSocket should only close if all
  // of it's sessions have closed. When those close, they will
  // remove themselves from the sockets list.
  [kMaybeClose]() {
    const { state, sessions } = this[kState];
    debug('Maybe close socket?');
    if (sessions.size === 0) {
      const doClose = () => {
        debug('Closing QuicSocket');
        this[kHandle].close();
        this[kState].state = kSocketUnbound;
        process.nextTick(emit.bind(this, 'close'));
      };
      if (state === kSocketPending ||
          state == kSocketClosing) {
        // TODO(jasnell): Decide if we really want to wait or interrupt
        debug('Deferring close until socket is ready');
        this.on('ready', doClose);
        return;
      }
      doClose();
    }
  }

  // The kReady function is called after the socket has been bound to the
  // local port. It signals when the various sessions may begin
  // doing their various things they do.
  [kReady](fd) {
    const { sessions } = this[kState];
    this[kState].state = kSocketBound;
    this[kState].fd = fd;
    for (const session of sessions)
      session[kReady]();
    debug(`QuicSocket is bound to FD ${fd} and ready for use`);
    process.nextTick(emit.bind(this, 'ready'));
  }

  // A socket should only be put into the receiving state if there is a
  // listening server or an active client. This will be called on demand
  // when needed.
  [kReceiveStart]() {
    // TODO(jasnell): Proper error handling here
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('kReceiveStart');
    this[kHandle].receiveStart();
  }

  // The socket should be moved to a not receiving state if there is no
  // listening server and no active sessions. This will be called on demand
  // when needed.
  [kReceiveStop]() {
    // TODO(jasnell): Proper error handling here
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('kReceiveStart');
    this[kHandle].receiveStop();
  }

  listen(options = {}, callback) {
    if (this[kState].serverListening)
      throw new ERR_QUICSOCKET_LISTENING();
    switch (this[kState].state) {
      case kSocketDestroyed:
        throw new ERR_QUICSOCKET_DESTROYED('createServer');
      case kSocketClosing:
        throw new ERR_QUICSOCKET_CLOSING('createServer');
      default:
        // Fall-through
    }

    this[kMaybeBind]();
    const sc = this[kState].serverSecureContext = createSecureContext(options);

    this[kState].serverListening = true;
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('session', callback);
    }

    const doListen = () => {
      this[kHandle].listen(sc.context);
      process.nextTick(emit.bind(this, 'listening'));
    };

    if (this[kState].state === kSocketPending) {
      this.on('ready', doListen);
      return;
    }
    doListen();
  }

  connect(options = {}) {
    switch (this[kState].state) {
      case kSocketDestroyed:
        throw new ERR_QUICSOCKET_DESTROYED('connect');
      case kSocketClosing:
        throw new ERR_QUICSOCKET_CLOSING('connect');
      default:
        // Fall-through
    }
    this[kMaybeBind]();
    const session = new QuicClientSession(options);
    this[kState].sessions.add(session);
    return session;
  }

  close(callback) {
    switch (this[kState].state) {
      case kSocketUnbound:
      case kSocketDestroyed:
      case kSocketClosing:
        return;
      default:
        // Fall-through
    }

    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }

    // Gracefully close the socket by signaling all of the client and server
    // instances to close.
    this[kState].state = kSocketClosing;
    const { sessions } = this[kState];
    const maybeClose = this[kMaybeClose].bind(this);
    for (const session of sessions)
      session.close(maybeClose);
  }

  destroy(error) {
    if (this.destroyed)
      return;
    debug(`QuicSocket::destroy[${error}]`);
    const { sessions } = this[kState];
    for (const session of sessions)
      session.destroy(error);

    this[kHandle].destroy();
    this[kState].state = kSocketDestroyed;

    if (error) process.nextTick(emit.bind(this, 'error', error));
    process.nextTick(emit.bind(this, 'close'));
  }

  ref() {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('ref');
    this[kHandle].ref();
  }

  unref() {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('unref');
    this[kHandle].unref();
  }

  get address() {
    if (this.destroyed)
      return;
    const out = {};
    const err = this[kHandle].getsockname(out);
    if (err)
      throw errnoException(err, 'address');
    return out;
  }

  get bound() {
    return this[kState].state === kSocketBound;
  }

  get pending() {
    return this[kState].state === kSocketPending;
  }

  get destroyed() {
    return this[kState].state === kSocketDestroyed;
  }

  get fd() {
    return this[kState].fd;
  }

  setTTL(ttl) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setTTL');
    if (typeof ttl !== 'number')
      throw new ERR_INVALID_ARG_TYPE('ttl', 'number', ttl);
    if (ttl < 1 || ttl > 255)
      throw new ERR_INVALID_ARG_VALUE('ttl', ttl);
    const err = this[kHandle].setTTL(ttl);
    if (err)
      throw errnoException(err, 'dropMembership')
  }

  setMulticastTTL(ttl) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastTTL');
    if (typeof ttl !== 'number')
      throw new ERR_INVALID_ARG_TYPE('ttl', 'number', ttl);
    if (ttl < 1 || ttl > 255)
      throw new ERR_INVALID_ARG_VALUE('ttl', ttl);
    const err = this[kHandle].setMulticastTTL(ttl);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setBroadcast(on = true) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setBroadcast');
    if (typeof on !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('on', 'boolean', on);
    const err = this[kHandle].setBroadcast(on);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setMulticastLoopback(on = true) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastLoopback');
    if (typeof on !== 'boolean')
      throw new ERR_INVALID_ARG_TYPE('on', 'boolean', on);
    const err = this[kHandle].setMulticastLoopback(on);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  setMulticastInterface(iface) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('setMulticastInterface');
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].setMulticastInterface(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  addMembership(address, iface) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('addMembership');
    if (typeof address !== 'string')
      throw new ERR_INVALID_ARG_TYPE('address', 'string', address);
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].addMembership(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
  }

  dropMembership(address, iface) {
    if (this.destroyed)
      throw new ERR_QUICSOCKET_DESTROYED('dropMembership');
    if (typeof address !== 'string')
      throw new ERR_INVALID_ARG_TYPE('address', 'string', address);
    if (typeof iface !== 'string')
      throw new ERR_INVALID_ARG_TYPE('iface', 'string', iface);
    const err = this[kHandle].dropMembership(iface);
    if (err)
      throw errnoException(err, 'dropMembership');
  }
}

function createSecureContext(options) {
  const {
    ca,
    cert,
    ciphers,
    clientCertEngine,
    crl,
    dhparam,
    ecdhCurve,
    honorCipherOrder,
    key,
    // maxVersion = 'TLSv1.3',
    // minVersion = 'TLSv1.3',
    passphrase,
    pfx,
    secureOptions,
    secureProtocol = 'TLSv1_3_method',
    sessionIdContext
  } = options;
  if (/*minVersion !== 'TLSv1.3' ||
      maxVersion !== 'TLSv1.3' || */
      secureProtocol !== 'TLSv1_3_method') {
    throw new ERR_QUIC_TLS13_REQUIRED();
  }
  return _createSecureContext({
    ca, cert, ciphers, clientCertEngine, crl, dhparam, ecdhCurve,
    honorCipherOrder, key, undefined, undefined, passphrase, pfx,
    secureOptions, secureProtocol, sessionIdContext
  });
}

class QuicSession extends EventEmitter {
  // Events:
  // * stream -- New Stream was Created
  // * error -- Error occurred
  // * ready -- Session is ready for use
  // * close -- Server is closed
  constructor(socket) {
    super();
    this[kState] = {
      socket,
      destroyed: false
    };
  }

  openStream(options) {
    if (this[kState].destroyed)
      throw new ERR_QUICSESSION_DESTROYED('close');
  }

  close(callback) {
    if (this[kState].destroyed)
      throw new ERR_QUICSESSION_DESTROYED('close');
    // TODO(jasnell): Gracefully close the session and all associated streams.
    // No new streams can be created or will be accepted.
    if (callback) {
      if (typeof callback !== 'function')
        throw new ERR_INVALID_CALLBACK();
      this.on('close', callback);
    }
  }

  destroy(error) {
    if (this[kState].destroyed)
      return;
    // TODO(jasnell): destroy the server properly
    this[kState].destroyed = true;
    if (error) process.nextTick(emit.bind(this, 'error', error));
    process.nextTick(emit.bind(this, 'close'));
  }

  get destroyed() {
    return this[kState].destroyed;
  }

  get socket() {
    return this[kState].socket;
  }
}

class QuicServerSession extends QuicSession {
  constructor(socket, handle) {
    super(socket);
    this[kHandle] = handle;
    handle[owner_symbol] = this;
  }

  [kReady]() {
    // TODO(jasnell): Socket is ready to go. This should be a non-op
  }
}

class QuicClientSession extends QuicSession {
  constructor(socket) {
    super(socket);
  }

  [kReady]() {
    // TODO(jasnell): Socket is ready to go
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
