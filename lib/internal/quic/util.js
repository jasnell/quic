'use strict';

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_QUICSESSION_INVALID_DCID,
    ERR_QUICSOCKET_INVALID_STATELESS_RESET_SECRET_LENGTH,
  },
} = require('internal/errors');

const { Buffer } = require('buffer');
const {
  isLegalPort,
  isIP,
} = require('internal/net');

const {
  getOptionValue,
  getAllowUnauthorized,
} = require('internal/options');

const {
  sessionConfig,
  http3Config,
  constants: {
    AF_INET,
    AF_INET6,
    DEFAULT_RETRYTOKEN_EXPIRATION,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_HOST,
    DEFAULT_MAX_STATELESS_RESETS_PER_HOST,
    IDX_QUIC_SESSION_ACTIVE_CONNECTION_ID_LIMIT,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI,
    IDX_QUIC_SESSION_MAX_DATA,
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI,
    IDX_QUIC_SESSION_MAX_STREAMS_UNI,
    IDX_QUIC_SESSION_MAX_IDLE_TIMEOUT,
    IDX_QUIC_SESSION_MAX_ACK_DELAY,
    IDX_QUIC_SESSION_MAX_PACKET_SIZE,
    IDX_QUIC_SESSION_CONFIG_COUNT,
    IDX_QUIC_SESSION_STATE_CERT_ENABLED,
    IDX_QUIC_SESSION_STATE_CLIENT_HELLO_ENABLED,
    IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED,
    IDX_QUIC_SESSION_STATE_PATH_VALIDATED_ENABLED,
    IDX_QUIC_SESSION_STATE_USE_PREFERRED_ADDRESS_ENABLED,
    IDX_HTTP3_QPACK_MAX_TABLE_CAPACITY,
    IDX_HTTP3_QPACK_BLOCKED_STREAMS,
    IDX_HTTP3_MAX_HEADER_LIST_SIZE,
    IDX_HTTP3_MAX_PUSHES,
    IDX_HTTP3_MAX_HEADER_PAIRS,
    IDX_HTTP3_MAX_HEADER_LENGTH,
    IDX_HTTP3_CONFIG_COUNT,
    MAX_RETRYTOKEN_EXPIRATION,
    MIN_RETRYTOKEN_EXPIRATION,
    NGTCP2_NO_ERROR,
    NGTCP2_MAX_CIDLEN,
    NGTCP2_MIN_CIDLEN,
    QUIC_PREFERRED_ADDRESS_IGNORE,
    QUIC_PREFERRED_ADDRESS_ACCEPT,
    QUIC_ERROR_APPLICATION,
  }
} = internalBinding('quic');

const {
  validateBoolean,
  validateBuffer,
  validateInteger,
  validateNumber,
  validateObject,
  validateString,
} = require('internal/validators');

let dns;

function lazyDNS() {
  if (!dns)
    dns = require('dns');
  return dns;
}

function getSocketType(type = 'udp4') {
  switch (type) {
    case 'udp4': return AF_INET;
    case 'udp6': return AF_INET6;
  }
  throw new ERR_INVALID_ARG_VALUE('options.type', type);
}

function lookup4(address, callback) {
  const { lookup } = lazyDNS();
  lookup(address || '127.0.0.1', 4, callback);
}

function lookup6(address, callback) {
  const { lookup } = lazyDNS();
  lookup(address || '::1', 6, callback);
}

function validateCloseCode(code) {
  if (code != null && typeof code === 'object') {
    return {
      closeCode: code.code || NGTCP2_NO_ERROR,
      closeFamily: code.family || QUIC_ERROR_APPLICATION,
    };
  } else if (typeof code === 'number') {
    return {
      closeCode: code,
      closeFamily: QUIC_ERROR_APPLICATION,
    };
  }
  throw new ERR_INVALID_ARG_TYPE('code', ['number', 'Object'], code);
}

function validateLookup(lookup) {
  if (lookup && typeof lookup !== 'function')
    throw new ERR_INVALID_ARG_TYPE('options.lookup', 'Function', lookup);
}

function validatePort(port, name) {
  if (!isLegalPort(port)) {
    throw new ERR_INVALID_ARG_VALUE(
      name, port,
      'is not a valid IP port');
  }
}

function validatePreferredAddress(address) {
  if (address !== undefined) {
    validateObject(address, 'options.preferredAddress');
    validateString(address.address, 'options.preferredAddress.address');
    if (address.port !== undefined)
      validatePort(address.port, 'options.preferredAddress.port');
    getSocketType(address.type);
  }
  return address;
}

// Validate known transport parameters, ignoring any that are not
// supported.  Ensures that only supported parameters are passed on.
function validateTransportParams(params) {
  const {
    activeConnectionIdLimit,
    maxStreamDataBidiLocal,
    maxStreamDataBidiRemote,
    maxStreamDataUni,
    maxData,
    maxStreamsBidi,
    maxStreamsUni,
    idleTimeout,
    maxPacketSize,
    maxAckDelay,
    preferredAddress,
    rejectUnauthorized,
    requestCert,
    h3: {
      qpackMaxTableCapacity,
      qpackBlockedStreams,
      maxHeaderListSize,
      maxPushes,
      maxHeaderPairs,
      maxHeaderLength = getOptionValue('--max-http-header-size'),
    },
  } = { h3: {}, ...params };

  validateInteger(
    activeConnectionIdLimit,
    'options.activeConnectionIdLimit',
    { min: 2, max: 8, allowUndefined: true });
  validateInteger(
    maxStreamDataBidiLocal,
    'options.maxStreamDataBidiLocal',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxStreamDataBidiRemote,
    'options.maxStreamDataBidiRemote',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxStreamDataUni,
    'options.maxStreamDataUni',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxData,
    'options.maxData',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxStreamsBidi,
    'options.maxStreamsBidi',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxStreamsUni,
    'options.maxStreamsUni',
    { min: 0, allowUndefined: true });
  validateInteger(
    idleTimeout,
    'options.idleTimeout',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxPacketSize,
    'options.maxPacketSize',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxAckDelay,
    'options.maxAckDelay',
    { min: 0, allowUndefined: true });
  validateInteger(
    qpackMaxTableCapacity,
    'options.h3.qpackMaxTableCapacity',
    { min: 0, allowUndefined: true });
  validateInteger(
    qpackBlockedStreams,
    'options.h3.qpackBlockedStreams',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxHeaderListSize,
    'options.h3.maxHeaderListSize',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxPushes,
    'options.h3.maxPushes',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxHeaderPairs,
    'options.h3.maxHeaderPairs',
    { min: 0, allowUndefined: true });
  validateInteger(
    maxHeaderLength,
    'options.h3.maxHeaderLength',
    { min: 0, allowUndefined: true });

  validatePreferredAddress(preferredAddress);

  return {
    activeConnectionIdLimit,
    maxStreamDataBidiLocal,
    maxStreamDataBidiRemote,
    maxStreamDataUni,
    maxData,
    maxStreamsBidi,
    maxStreamsUni,
    idleTimeout,
    maxPacketSize,
    maxAckDelay,
    preferredAddress,
    rejectUnauthorized,
    requestCert,
    h3: {
      qpackMaxTableCapacity,
      qpackBlockedStreams,
      maxHeaderListSize,
      maxPushes,
      maxHeaderPairs,
      maxHeaderLength,
    }
  };
}

function validateQuicClientSessionOptions(options = {}) {
  if (options !== null && typeof options !== 'object')
    throw new ERR_INVALID_ARG_TYPE('options', 'Object', options);
  const {
    address = 'localhost',
    alpn = '',
    dcid: dcid_value,
    ipv6Only = false,
    minDHSize = 1024,
    port = 0,
    preferredAddressPolicy = 'ignore',
    remoteTransportParams,
    requestOCSP = false,
    servername = (isIP(address) ? '' : address),
    sessionTicket,
    verifyHostnameIdentity = true,
    qlog = false,
  } = options;

  validateNumber(minDHSize, 'options.minDHSize');
  validatePort(port, 'options.port');
  validateString(address, 'options.address');
  validateString(alpn, 'options.alpn');
  validateString(servername, 'options.servername');

  if (isIP(servername)) {
    throw new ERR_INVALID_ARG_VALUE(
      'options.servername',
      servername,
      'cannot be an IP address');
  }

  validateBuffer(
    remoteTransportParams,
    'options.remoteTransportParams',
    { allowUndefined: true });

  validateBuffer(
    sessionTicket,
    'options.sessionTicket',
    { allowUndefined: true });

  let dcid;
  if (dcid_value !== undefined) {
    if (typeof dcid_value === 'string') {
      // If it's a string, it must be a hex encoded string
      try {
        dcid = Buffer.from(dcid_value, 'hex');
      } catch {
        throw new ERR_QUICSESSION_INVALID_DCID(dcid);
      }
    }

    validateBuffer(
      dcid_value,
      'options.dcid',
      ['string', 'Buffer', 'TypedArray', 'DataView']);

    if (dcid_value.length > NGTCP2_MAX_CIDLEN ||
        dcid_value.length < NGTCP2_MIN_CIDLEN) {
      throw new ERR_QUICSESSION_INVALID_DCID(dcid_value.toString('hex'));
    }

    dcid = dcid_value;
  }

  if (preferredAddressPolicy !== undefined)
    validateString(preferredAddressPolicy, 'options.preferredAddressPolicy');

  validateBoolean(ipv6Only, 'options.ipv6Only');
  validateBoolean(requestOCSP, 'options.requestOCSP');
  validateBoolean(verifyHostnameIdentity, 'options.verifyHostnameIdentity');
  validateBoolean(qlog, 'options.qlog');

  return {
    address,
    alpn,
    dcid,
    ipv6Only,
    minDHSize,
    port,
    preferredAddressPolicy:
      preferredAddressPolicy === 'accept' ?
        QUIC_PREFERRED_ADDRESS_ACCEPT :
        QUIC_PREFERRED_ADDRESS_IGNORE,
    remoteTransportParams,
    requestOCSP,
    servername,
    sessionTicket,
    verifyHostnameIdentity,
    qlog,
  };
}

function validateQuicEndpointOptions(options = {}, name = 'options') {
  validateObject(options, name);
  if (options === null || typeof options !== 'object')
    throw new ERR_INVALID_ARG_TYPE('options', 'Object', options);
  const {
    address,
    ipv6Only = false,
    lookup,
    port = 0,
    reuseAddr = false,
    type = 'udp4',
    preferred = false,
  } = options;
  validateString(address, 'options.address', { allowUndefined: true });
  validatePort(port, 'options.port');
  validateString(type, 'options.type');
  validateLookup(lookup);
  validateBoolean(ipv6Only, 'options.ipv6Only');
  validateBoolean(reuseAddr, 'options.reuseAddr');
  validateBoolean(preferred, 'options.preferred');
  return {
    address,
    ipv6Only,
    lookup,
    port,
    preferred,
    reuseAddr,
    type: getSocketType(type),
  };
}

function validateQuicSocketOptions(options = {}) {
  validateObject(options, 'options');

  const {
    autoClose = false,
    client = {},
    disableStatelessReset = false,
    endpoint = { port: 0, type: 'udp4' },
    lookup,
    maxConnections = DEFAULT_MAX_CONNECTIONS,
    maxConnectionsPerHost = DEFAULT_MAX_CONNECTIONS_PER_HOST,
    maxStatelessResetsPerHost = DEFAULT_MAX_STATELESS_RESETS_PER_HOST,
    qlog = false,
    retryTokenTimeout = DEFAULT_RETRYTOKEN_EXPIRATION,
    server = {},
    statelessResetSecret,
    type = endpoint.type || 'udp4',
    validateAddressLRU = false,
    validateAddress = false,
  } = options;

  validateQuicEndpointOptions(endpoint, 'options.endpoint');
  validateObject(client, 'options.client');
  validateObject(server, 'options.server');
  validateString(type, 'options.type');
  validateLookup(lookup);
  validateBoolean(validateAddress, 'options.validateAddress');
  validateBoolean(validateAddressLRU, 'options.validateAddressLRU');
  validateBoolean(autoClose, 'options.autoClose');
  validateBoolean(qlog, 'options.qlog');
  validateBoolean(disableStatelessReset, 'options.disableStatelessReset');

  validateInteger(
    retryTokenTimeout,
    'options.retryTokenTimeout',
    {
      min: MIN_RETRYTOKEN_EXPIRATION,
      max: MAX_RETRYTOKEN_EXPIRATION,
      allowUndefined: true
    });
  validateInteger(
    maxConnections,
    'options.maxConnections',
    { min: 1, allowUndefined: true });
  validateInteger(
    maxConnectionsPerHost,
    'options.maxConnectionsPerHost',
    { min: 1, allowUndefined: true });
  validateInteger(
    maxStatelessResetsPerHost,
    'options.maxStatelessResetsPerHost',
    { min: 1, allowUndefined: true });

  if (statelessResetSecret !== undefined) {
    validateBuffer(statelessResetSecret, 'options.statelessResetSecret');
    if (statelessResetSecret.length !== 16)
      throw new ERR_QUICSOCKET_INVALID_STATELESS_RESET_SECRET_LENGTH();
  }

  return {
    endpoint,
    autoClose,
    client,
    lookup,
    maxConnections,
    maxConnectionsPerHost,
    maxStatelessResetsPerHost,
    retryTokenTimeout,
    server,
    type: getSocketType(type),
    validateAddress: validateAddress || validateAddressLRU,
    validateAddressLRU,
    qlog,
    statelessResetSecret,
    disableStatelessReset,
  };
}

function setConfigField(buffer, val, index) {
  if (typeof val === 'number') {
    buffer[index] = val;
    return 1 << index;
  }
  return 0;
}

// Extracts configuration options and updates the aliased buffer
// arrays that are used to communicate config choices to the c++
// internals.
function setTransportParams(config) {
  const {
    activeConnectionIdLimit,
    maxStreamDataBidiLocal,
    maxStreamDataBidiRemote,
    maxStreamDataUni,
    maxData,
    maxStreamsBidi,
    maxStreamsUni,
    idleTimeout,
    maxPacketSize,
    maxAckDelay,
    h3: {
      qpackMaxTableCapacity,
      qpackBlockedStreams,
      maxHeaderListSize,
      maxPushes,
      maxHeaderPairs,
      maxHeaderLength,
    },
  } = { h3: {}, ...config };

  // The const flags is a bitmap that is used to communicate whether or not a
  // given configuration value has been explicitly provided.
  const flags = setConfigField(sessionConfig,
                               activeConnectionIdLimit,
                               IDX_QUIC_SESSION_ACTIVE_CONNECTION_ID_LIMIT) |
                setConfigField(sessionConfig,
                               maxStreamDataBidiLocal,
                               IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL) |
                setConfigField(sessionConfig,
                               maxStreamDataBidiRemote,
                               IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE) |
                setConfigField(sessionConfig,
                               maxStreamDataUni,
                               IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI) |
                setConfigField(sessionConfig,
                               maxData,
                               IDX_QUIC_SESSION_MAX_DATA) |
                setConfigField(sessionConfig,
                               maxStreamsBidi,
                               IDX_QUIC_SESSION_MAX_STREAMS_BIDI) |
                setConfigField(sessionConfig,
                               maxStreamsUni,
                               IDX_QUIC_SESSION_MAX_STREAMS_UNI) |
                setConfigField(sessionConfig,
                               idleTimeout,
                               IDX_QUIC_SESSION_MAX_IDLE_TIMEOUT) |
                setConfigField(sessionConfig,
                               maxAckDelay,
                               IDX_QUIC_SESSION_MAX_ACK_DELAY) |
                setConfigField(sessionConfig,
                               maxPacketSize,
                               IDX_QUIC_SESSION_MAX_PACKET_SIZE);

  sessionConfig[IDX_QUIC_SESSION_CONFIG_COUNT] = flags;

  const h3flags = setConfigField(http3Config,
                                 qpackMaxTableCapacity,
                                 IDX_HTTP3_QPACK_MAX_TABLE_CAPACITY) |
                  setConfigField(http3Config,
                                 qpackBlockedStreams,
                                 IDX_HTTP3_QPACK_BLOCKED_STREAMS) |
                  setConfigField(http3Config,
                                 maxHeaderListSize,
                                 IDX_HTTP3_MAX_HEADER_LIST_SIZE) |
                  setConfigField(http3Config,
                                 maxPushes,
                                 IDX_HTTP3_MAX_PUSHES) |
                  setConfigField(http3Config,
                                 maxHeaderPairs,
                                 IDX_HTTP3_MAX_HEADER_PAIRS) |
                  setConfigField(http3Config,
                                 maxHeaderLength,
                                 IDX_HTTP3_MAX_HEADER_LENGTH);

  http3Config[IDX_HTTP3_CONFIG_COUNT] = h3flags;
}

// Some events that are emitted originate from the C++ internals and are
// fairly expensive and optional. An aliased array buffer is used to
// communicate that a handler has been added for the optional events
// so that the C++ internals know there is an actual listener. The event
// will not be emitted if there is no handler.
function toggleListeners(handle, event, on) {
  if (handle === undefined)
    return;
  const val = on ? 1 : 0;
  switch (event) {
    case 'keylog':
      handle.state[IDX_QUIC_SESSION_STATE_KEYLOG_ENABLED] = val;
      break;
    case 'clientHello':
      handle.state[IDX_QUIC_SESSION_STATE_CLIENT_HELLO_ENABLED] = val;
      break;
    case 'pathValidation':
      handle.state[IDX_QUIC_SESSION_STATE_PATH_VALIDATED_ENABLED] = val;
      break;
    case 'OCSPRequest':
      handle.state[IDX_QUIC_SESSION_STATE_CERT_ENABLED] = val;
      break;
    case 'usePreferredAddress':
      handle.state[IDX_QUIC_SESSION_STATE_USE_PREFERRED_ADDRESS_ENABLED] = on;
      break;
  }
}

module.exports = {
  getAllowUnauthorized,
  getSocketType,
  lookup4,
  lookup6,
  setTransportParams,
  toggleListeners,
  validateCloseCode,
  validateTransportParams,
  validateQuicClientSessionOptions,
  validateQuicSocketOptions,
  validateQuicEndpointOptions,
};
