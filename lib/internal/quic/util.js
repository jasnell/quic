'use strict';

const {
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_ARG_VALUE,
    ERR_OUT_OF_RANGE,
    ERR_QUICSESSION_INVALID_DCID,
  },
} = require('internal/errors');

const { isArrayBufferView } = require('internal/util/types');
const {
  isLegalPort,
  isIP,
} = require('internal/net');

const {
  constants: {
    AF_INET,
    AF_INET6,
    DEFAULT_RETRYTOKEN_EXPIRATION,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI_DEFAULT,
    IDX_QUIC_SESSION_MAX_DATA_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI_DEFAULT,
    IDX_QUIC_SESSION_MAX_STREAMS_UNI_DEFAULT,
    IDX_QUIC_SESSION_IDLE_TIMEOUT_DEFAULT,
    IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT,
    MAX_RETRYTOKEN_EXPIRATION,
    MIN_RETRYTOKEN_EXPIRATION,
    NGTCP2_DEFAULT_MAX_ACK_DELAY,
    NGTCP2_MAX_CIDLEN,
    NGTCP2_MIN_CIDLEN,
    QUIC_PREFERRED_ADDRESS_IGNORE,
    QUIC_PREFERRED_ADDRESS_ACCEPT,
  }
} = internalBinding('quic');

let warnOnAllowUnauthorized = true;
let dns;

function lazyDNS() {
  if (!dns)
    dns = require('dns');
  return dns;
}

function getAllowUnauthorized() {
  const allowUnauthorized = process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0';

  if (allowUnauthorized && warnOnAllowUnauthorized) {
    warnOnAllowUnauthorized = false;
    process.emitWarning(
      'Setting the NODE_TLS_REJECT_UNAUTHORIZED ' +
      'environment variable to \'0\' makes TLS connections ' +
      'and HTTPS requests insecure by disabling ' +
      'certificate verification.');
  }
  return allowUnauthorized;
}

function getSocketType(type) {
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

function validateBindOptions(port, address) {
  if (!isLegalPort(port)) {
    throw new ERR_INVALID_ARG_VALUE(
      'options.port', port, 'is not a valid IP port');
  }
  if (address != null && typeof address !== 'string')
    throw new ERR_INVALID_ARG_TYPE('options.address', 'string', address);
}

function validateNumberInRange(val, name, range) {
  if (!Number.isSafeInteger(val))
    throw new ERR_INVALID_ARG_TYPE(name, 'number', val);
  if (val < 0)
    throw new ERR_OUT_OF_RANGE(name, range, val);
}

function validateNumberInBoundedRange(val, name, min, max) {
  if (!Number.isSafeInteger(val))
    throw new ERR_INVALID_ARG_TYPE(name, 'number', val);
  if (val < min || val > max)
    throw new ERR_OUT_OF_RANGE(name, `${min} <= ${name} <= ${max}`, val);
}

function validateTransportParams(params, maxCidLen, minCidLen) {
  const {
    maxStreamDataBidiLocal =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_LOCAL_DEFAULT,
    maxStreamDataBidiRemote =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_BIDI_REMOTE_DEFAULT,
    maxStreamDataUni =
    IDX_QUIC_SESSION_MAX_STREAM_DATA_UNI_DEFAULT,
    maxData =
    IDX_QUIC_SESSION_MAX_DATA_DEFAULT,
    maxStreamsBidi =
    IDX_QUIC_SESSION_MAX_STREAMS_BIDI_DEFAULT,
    maxStreamsUni =
    IDX_QUIC_SESSION_MAX_STREAMS_UNI_DEFAULT,
    idleTimeout =
    IDX_QUIC_SESSION_IDLE_TIMEOUT_DEFAULT,
    maxPacketSize =
    IDX_QUIC_SESSION_MAX_PACKET_SIZE_DEFAULT,
    maxAckDelay = NGTCP2_DEFAULT_MAX_ACK_DELAY,
    preferredAddress,
  } = { ...params };
  validateNumberInRange(
    maxStreamDataBidiLocal,
    'options.maxStreamDataBidiLocal',
    '>=0');
  validateNumberInRange(
    maxStreamDataBidiRemote,
    'options.maxStreamDataBidiRemote',
    '>=0');
  validateNumberInRange(
    maxStreamDataUni,
    'options.maxStreamDataUni',
    '>=0');
  validateNumberInRange(
    maxData,
    'options.maxData',
    '>=0');
  validateNumberInRange(
    maxStreamsBidi,
    'options.maxStreamsBidi',
    '>=0');
  validateNumberInRange(
    maxStreamsUni,
    'options.maxStreamsUni',
    '>=0');
  validateNumberInRange(
    idleTimeout,
    'options.idleTimeout',
    '>=0');
  validateNumberInRange(
    maxPacketSize,
    'options.maxPacketSize',
    '>=0');
  validateNumberInRange(
    maxAckDelay,
    'options.maxAckDelay',
    '>=0');
  return {
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
    maxCidLen,
    minCidLen,
  };
}

function validateQuicClientSessionOptions(options) {
  const {
    address,
    servername = address,
    port = 0,
    ipv6Only = false,
    minDHSize = 1024,
    remoteTransportParams,
    sessionTicket,
    dcid: dcid_value,
    maxCidLen = NGTCP2_MAX_CIDLEN,
    minCidLen = NGTCP2_MIN_CIDLEN,
    preferredAddressPolicy = 'ignore',
  } = { ...options };

  if (typeof minDHSize !== 'number')
    throw new ERR_INVALID_ARG_TYPE(
      'options.minDHSize', 'number', minDHSize);

  if (!isLegalPort(port)) {
    throw new ERR_INVALID_ARG_VALUE(
      'options.port', port,
      'is not a valid IP port');
  }

  if (servername && typeof servername !== 'string') {
    throw new ERR_INVALID_ARG_TYPE(
      'options.servername', 'string', servername);
  }
  if (isIP(servername)) {
    throw new ERR_INVALID_ARG_VALUE(
      'options.servername', servername, 'cannot be an IP address');
  }

  if (remoteTransportParams && !isArrayBufferView(remoteTransportParams)) {
    throw new ERR_INVALID_ARG_TYPE(
      'options.remoteTransportParams',
      ['Buffer', 'TypedArray', 'DataView'],
      remoteTransportParams);
  }
  if (sessionTicket && !isArrayBufferView(sessionTicket)) {
    throw new ERR_INVALID_ARG_TYPE(
      'options.sessionTicket',
      ['Buffer', 'TypedArray', 'DataView'],
      sessionTicket);
  }

  validateNumberInBoundedRange(
    maxCidLen,
    'options.maxCidLen',
    NGTCP2_MIN_CIDLEN,
    NGTCP2_MAX_CIDLEN);

  validateNumberInBoundedRange(
    minCidLen,
    'options.minCidLen',
    NGTCP2_MIN_CIDLEN,
    NGTCP2_MAX_CIDLEN);

  if (minCidLen > maxCidLen) {
    throw new ERR_OUT_OF_RANGE(
      'options.minCidLen',
      `<= ${maxCidLen}`,
      minCidLen);
  }

  let dcid;
  if (dcid_value !== undefined) {
    if (typeof dcid_value === 'string') {
      // If it's a string, it must be a hex encoded string
      try {
        dcid = Buffer.from(dcid_value, 'hex');
      } catch(err) {
        throw new ERR_QUICSESSION_INVALID_DCID(dcid);
      }
    } else if (!isArrayBufferView(dcid_value)) {
      throw new ERR_INVALID_ARG_TYPE(
        'options.dcid',
        ['string', 'Buffer', 'TypedArray', 'DataView'],
        dcid);
    } else {
      dcid = dcid_value;
    }
    if (dcid.length > maxCidLen ||
        dcid.length < minCidLen) {
      throw new ERR_QUICSESSION_INVALID_DCID(dcid.toString('hex'));
    }
  }

  if (preferredAddressPolicy !== undefined &&
      typeof preferredAddressPolicy !== 'string') {
    throw new ERR_INVALID_ARG_TYPE(
      'options.preferredAddressPolicy',
      'string',
      preferredAddressPolicy);
  }

  return {
    address,
    servername,
    port,
    ipv6Only,
    minDHSize,
    remoteTransportParams,
    sessionTicket,
    dcid,
    maxCidLen,
    minCidLen,
    preferredAddressPolicy:
      preferredAddressPolicy === 'accept' ?
        QUIC_PREFERRED_ADDRESS_ACCEPT :
        QUIC_PREFERRED_ADDRESS_IGNORE,
  };
}

function validateQuicSocketOptions(options) {
  const {
    address,
    client,
    ipv6Only = false,
    lookup,
    port = 0,
    reuseAddr = false,
    server,
    type = 'udp4',
    validateAddress = false,
    retryTokenTimeout = DEFAULT_RETRYTOKEN_EXPIRATION,
  } = { ...options };
  validateBindOptions(port, address);
  if (typeof type !== 'string')
    throw new ERR_INVALID_ARG_TYPE('options.type', 'string', type);
  if (lookup && typeof lookup !== 'function')
    throw new ERR_INVALID_ARG_TYPE('options.lookup', 'Function', lookup);
  if (typeof ipv6Only !== 'boolean')
    throw new ERR_INVALID_ARG_TYPE('options.ipv6Only', 'boolean', ipv6Only);
  if (typeof reuseAddr !== 'boolean')
    throw new ERR_INVALID_ARG_TYPE('options.reuseAddr', 'boolean', reuseAddr);
  if (typeof validateAddress !== 'boolean') {
    throw new ERR_INVALID_ARG_TYPE(
      'options.validateAddress',
      'boolean',
      validateAddress);
  }
  validateNumberInBoundedRange(
    retryTokenTimeout,
    'options.retryTokenTimeout',
    MIN_RETRYTOKEN_EXPIRATION,
    MAX_RETRYTOKEN_EXPIRATION);
  return {
    address,
    client,
    ipv6Only,
    lookup,
    port,
    retryTokenTimeout,
    reuseAddr,
    server,
    type: getSocketType(type),
    validateAddress
  };
}


module.exports = {
  getAllowUnauthorized,
  getSocketType,
  lookup4,
  lookup6,
  validateBindOptions,
  validateNumberInRange,
  validateTransportParams,
  validateQuicClientSessionOptions,
  validateQuicSocketOptions,
};