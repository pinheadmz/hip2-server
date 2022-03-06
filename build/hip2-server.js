/*!
 * hip2-server@1.0.0
 * Copyright (c) 2022, Matthew Zipkin (MIT)
 * https://github.com/pinheadmz/hip2-server#readme
 */

var __node_modules__ = [
[/* 0 */ 'hip2-server', '/src/derive.js', function(exports, module, __filename, __dirname, __meta) {
'use strict';

const HDPublicKey = __node_require__(1 /* 'hsd/lib/hd/public' */);
const Address = __node_require__(55 /* 'hsd/lib/primitives/address' */);
const fs = require('fs');
const path = require('path');
const http = require('http');

const MAX_INDEX = 0x7fffffff;

if (process.argv.length < 3)
  throw new Error('Usage: node build/hip2-server.js <PORT>');
const port = process.argv[2];

const xpubFile = path.join(__dirname, '..', 'conf', 'xpub');
let xpub;
try {
  xpub = fs.readFileSync(xpubFile, 'ascii');
} catch (e) {
  throw new Error('xpub file missing');
}
xpub = xpub.split('\n')[0];

if (xpub === 'xpub6DBMpym6PM3qe7Ug7BwG6zo7dinMMjpk8nmb73czsjkzPTzfQ1d5ZvqDea4uNmMVv1Y9DT6v17GuDL1x2km9FQuKqWMdnrDfRiDNrG1nTMr')
  throw new Error('Example xpub must not be used! Repalce with your own account xpub.');

const acct = HDPublicKey.fromBase58(xpub);
const recv = acct.derive(0);

function addr() {
  const indexFile = path.join(__dirname, '..', 'log', 'hip2-index');
  let index = 0;
  try {
    index = parseInt(fs.readFileSync(indexFile));
  } catch (e) {
    ;
  }

  fs.writeFileSync(indexFile, index + 1);

  // Wow, used all our non-hardened addresses!
  // Don't roll over the saved index (that way the user knows this has happened)
  // but start over the address space and reuse addresses starting again at 0.
  if (index >= MAX_INDEX)
    index -= MAX_INDEX;

  const pk = recv.derive(index);
  const addr = Address.fromPubkey(pk.publicKey).toString();
  return addr;
}

const requestListener = function (req, res) {
  res.writeHead(200);
  res.end(addr());
};

const server = http.createServer(requestListener);
server.listen({port});
}],
[/* 1 */ 'hsd', '/lib/hd/public.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * public.js - hd public keys for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = __node_require__(2 /* 'bsert' */);
const bio = __node_require__(3 /* 'bufio' */);
const base58 = __node_require__(12 /* 'bcrypto/lib/encoding/base58' */);
const sha512 = __node_require__(15 /* 'bcrypto/lib/sha512' */);
const hash160 = __node_require__(18 /* 'bcrypto/lib/hash160' */);
const hash256 = __node_require__(22 /* 'bcrypto/lib/hash256' */);
const cleanse = __node_require__(24 /* 'bcrypto/lib/cleanse' */);
const secp256k1 = __node_require__(28 /* 'bcrypto/lib/secp256k1' */);
const Network = __node_require__(44 /* '../protocol/network' */);
const consensus = __node_require__(51 /* '../protocol/consensus' */);
const common = __node_require__(52 /* './common' */);

/**
 * HDPublicKey
 * @alias module:hd.PublicKey
 * @property {Number} depth
 * @property {Number} parentFingerPrint
 * @property {Number} childIndex
 * @property {Buffer} chainCode
 * @property {Buffer} publicKey
 */

class HDPublicKey extends bio.Struct {
  /**
   * Create an HD public key.
   * @constructor
   * @param {Object|Base58String} options
   * @param {Base58String?} options.xkey - Serialized base58 key.
   * @param {Number?} options.depth
   * @param {Number?} options.parentFingerPrint
   * @param {Number?} options.childIndex
   * @param {Buffer?} options.chainCode
   * @param {Buffer?} options.publicKey
   */

  constructor(options) {
    super();

    this.depth = 0;
    this.parentFingerPrint = 0;
    this.childIndex = 0;
    this.chainCode = consensus.ZERO_HASH;
    this.publicKey = common.ZERO_KEY;

    this.fingerPrint = -1;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'No options for HDPublicKey');
    assert((options.depth & 0xff) === options.depth);
    assert((options.parentFingerPrint >>> 0) === options.parentFingerPrint);
    assert((options.childIndex >>> 0) === options.childIndex);
    assert(Buffer.isBuffer(options.chainCode));
    assert(Buffer.isBuffer(options.publicKey));

    this.depth = options.depth;
    this.parentFingerPrint = options.parentFingerPrint;
    this.childIndex = options.childIndex;
    this.chainCode = options.chainCode;
    this.publicKey = options.publicKey;

    return this;
  }

  /**
   * Get HD public key (self).
   * @returns {HDPublicKey}
   */

  toPublic() {
    return this;
  }

  /**
   * Get cached base58 xprivkey (always null here).
   * @returns {null}
   */

  xprivkey(network) {
    return null;
  }

  /**
   * Get cached base58 xpubkey.
   * @returns {Base58String}
   */

  xpubkey(network) {
    return this.toBase58(network);
  }

  /**
   * Destroy the key (zeroes chain code and pubkey).
   */

  destroy() {
    this.depth = 0;
    this.childIndex = 0;
    this.parentFingerPrint = 0;

    cleanse(this.chainCode);
    cleanse(this.publicKey);

    this.fingerPrint = -1;
  }

  /**
   * Derive a child key.
   * @param {Number} index - Derivation index.
   * @param {Boolean?} hardened - Whether the derivation
   * should be hardened (throws if true).
   * @returns {HDPrivateKey}
   * @throws on `hardened`
   */

  derive(index, hardened) {
    assert(typeof index === 'number');

    if ((index >>> 0) !== index)
      throw new Error('Index out of range.');

    if ((index & common.HARDENED) || hardened)
      throw new Error('Cannot derive hardened.');

    if (this.depth >= 0xff)
      throw new Error('Depth too high.');

    const id = this.getID(index);
    const cache = common.cache.get(id);

    if (cache)
      return cache;

    const bw = bio.pool(37);

    bw.writeBytes(this.publicKey);
    bw.writeU32BE(index);

    const data = bw.render();

    const hash = sha512.mac(data, this.chainCode);
    const left = hash.slice(0, 32);
    const right = hash.slice(32, 64);

    let key;
    try {
      key = secp256k1.publicKeyTweakAdd(this.publicKey, left, true);
    } catch (e) {
      return this.derive(index + 1);
    }

    if (this.fingerPrint === -1) {
      const fp = hash160.digest(this.publicKey);
      this.fingerPrint = fp.readUInt32BE(0, true);
    }

    const child = new this.constructor();
    child.depth = this.depth + 1;
    child.parentFingerPrint = this.fingerPrint;
    child.childIndex = index;
    child.chainCode = right;
    child.publicKey = key;

    common.cache.set(id, child);

    return child;
  }

  /**
   * Unique HD key ID.
   * @private
   * @param {Number} index
   * @returns {String}
   */

  getID(index) {
    return 'b' + this.publicKey.toString('hex') + index;
  }

  /**
   * Derive a BIP44 account key (does not derive, only ensures account key).
   * @method
   * @param {Number} purpose
   * @param {Number} type
   * @param {Number} account
   * @returns {HDPublicKey}
   * @throws Error if key is not already an account key.
   */

  deriveAccount(purpose, type, account) {
    assert((purpose >>> 0) === purpose);
    assert((type >>> 0) === type);
    assert((account >>> 0) === account);
    assert(this.isAccount(account), 'Cannot derive account index.');
    return this;
  }

  /**
   * Test whether the key is a master key.
   * @method
   * @returns {Boolean}
   */

  isMaster() {
    return common.isMaster(this);
  }

  /**
   * Test whether the key is (most likely) a BIP44 account key.
   * @method
   * @param {Number?} account
   * @returns {Boolean}
   */

  isAccount(account) {
    return common.isAccount(this, account);
  }

  /**
   * Test whether a string is a valid path.
   * @param {String} path
   * @param {Boolean?} hardened
   * @returns {Boolean}
   */

  static isValidPath(path) {
    try {
      common.parsePath(path, false);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Derive a key from a derivation path.
   * @param {String} path
   * @returns {HDPublicKey}
   * @throws Error if `path` is not a valid path.
   * @throws Error if hardened.
   */

  derivePath(path) {
    const indexes = common.parsePath(path, false);

    let key = this;

    for (const index of indexes)
      key = key.derive(index);

    return key;
  }

  /**
   * Compare a key against an object.
   * @param {Object} obj
   * @returns {Boolean}
   */

  equals(obj) {
    assert(HDPublicKey.isHDPublicKey(obj));

    return this.depth === obj.depth
      && this.parentFingerPrint === obj.parentFingerPrint
      && this.childIndex === obj.childIndex
      && this.chainCode.equals(obj.chainCode)
      && this.publicKey.equals(obj.publicKey);
  }

  /**
   * Compare a key against an object.
   * @param {Object} obj
   * @returns {Boolean}
   */

  compare(key) {
    assert(HDPublicKey.isHDPublicKey(key));

    let cmp = this.depth - key.depth;

    if (cmp !== 0)
      return cmp;

    cmp = this.parentFingerPrint - key.parentFingerPrint;

    if (cmp !== 0)
      return cmp;

    cmp = this.childIndex - key.childIndex;

    if (cmp !== 0)
      return cmp;

    cmp = this.chainCode.compare(key.chainCode);

    if (cmp !== 0)
      return cmp;

    cmp = this.publicKey.compare(key.publicKey);

    if (cmp !== 0)
      return cmp;

    return 0;
  }

  /**
   * Convert key to a more json-friendly object.
   * @returns {Object}
   */

  getJSON(network) {
    return {
      xpubkey: this.xpubkey(network)
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   * @param {Network?} network
   */

  fromJSON(json, network) {
    assert(json.xpubkey, 'Could not handle HD key JSON.');
    this.fromBase58(json.xpubkey, network);
    return this;
  }

  /**
   * Test whether an object is in the form of a base58 xpubkey.
   * @param {String} data
   * @param {(Network|NetworkType)?} network
   * @returns {Boolean}
   */

  static isBase58(data, network) {
    if (typeof data !== 'string')
      return false;

    if (data.length < 4)
      return false;

    const prefix = data.substring(0, 4);

    try {
      Network.fromPublic58(prefix, network);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Test whether a buffer has a valid network prefix.
   * @param {Buffer} data
   * @param {(Network|NetworkType)?} network
   * @returns {NetworkType}
   */

  static isRaw(data, network) {
    if (!Buffer.isBuffer(data))
      return false;

    if (data.length < 4)
      return false;

    const version = data.readUInt32BE(0, true);

    try {
      Network.fromPublic(version, network);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Inject properties from a base58 key.
   * @private
   * @param {Base58String} xkey
   * @param {Network?} network
   */

  fromBase58(xkey, network) {
    assert(typeof xkey === 'string');
    return this.decode(base58.decode(xkey), network);
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {BufferReader} br
   * @param {(Network|NetworkType)?} network
   */

  read(br, network) {
    const version = br.readU32BE();

    Network.fromPublic(version, network);

    this.depth = br.readU8();
    this.parentFingerPrint = br.readU32BE();
    this.childIndex = br.readU32BE();
    this.chainCode = br.readBytes(32);
    this.publicKey = br.readBytes(33);

    br.verifyChecksum(hash256.digest);

    return this;
  }

  /**
   * Serialize key data to base58 extended key.
   * @param {(Network|NetworkType)?} network
   * @returns {Base58String}
   */

  toBase58(network) {
    return base58.encode(this.encode(network));
  }

  /**
   * Write the key to a buffer writer.
   * @param {BufferWriter} bw
   * @param {(Network|NetworkType)?} network
   */

  write(bw, network) {
    network = Network.get(network);

    bw.writeU32BE(network.keyPrefix.xpubkey);
    bw.writeU8(this.depth);
    bw.writeU32BE(this.parentFingerPrint);
    bw.writeU32BE(this.childIndex);
    bw.writeBytes(this.chainCode);
    bw.writeBytes(this.publicKey);
    bw.writeChecksum(hash256.digest);

    return bw;
  }

  /**
   * Calculate serialization size.
   * @returns {Number}
   */

  getSize() {
    return 82;
  }

  /**
   * Instantiate an HD public key from a base58 string.
   * @param {Base58String} xkey
   * @param {Network?} network
   * @returns {HDPublicKey}
   */

  static fromBase58(xkey, network) {
    return new this().fromBase58(xkey, network);
  }

  /**
   * Test whether an object is a HDPublicKey.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isHDPublicKey(obj) {
    return obj instanceof HDPublicKey;
  }
}

/*
 * Expose
 */

module.exports = HDPublicKey;
}],
[/* 2 */ 'bsert', '/lib/assert.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * assert.js - assertions for javascript
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/bsert
 */

'use strict';

/**
 * AssertionError
 */

class AssertionError extends Error {
  constructor(options) {
    if (typeof options === 'string')
      options = { message: options };

    if (options === null || typeof options !== 'object')
      options = {};

    let message = null;
    let operator = 'fail';
    let generatedMessage = Boolean(options.generatedMessage);

    if (options.message != null)
      message = toString(options.message);

    if (typeof options.operator === 'string')
      operator = options.operator;

    if (message == null) {
      if (operator === 'fail') {
        message = 'Assertion failed.';
      } else {
        const a = stringify(options.actual);
        const b = stringify(options.expected);

        message = `${a} ${operator} ${b}`;
      }

      generatedMessage = true;
    }

    super(message);

    let start = this.constructor;

    if (typeof options.stackStartFunction === 'function')
      start = options.stackStartFunction;
    else if (typeof options.stackStartFn === 'function')
      start = options.stackStartFn;

    this.type = 'AssertionError';
    this.name = 'AssertionError [ERR_ASSERTION]';
    this.code = 'ERR_ASSERTION';
    this.generatedMessage = generatedMessage;
    this.actual = options.actual;
    this.expected = options.expected;
    this.operator = operator;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, start);
  }
}

/*
 * Assert
 */

function assert(value, message) {
  if (!value) {
    let generatedMessage = false;

    if (arguments.length === 0) {
      message = 'No value argument passed to `assert()`.';
      generatedMessage = true;
    } else if (message == null) {
      message = 'Assertion failed.';
      generatedMessage = true;
    } else if (isError(message)) {
      throw message;
    }

    throw new AssertionError({
      message,
      actual: value,
      expected: true,
      operator: '==',
      generatedMessage,
      stackStartFn: assert
    });
  }
}

function equal(actual, expected, message) {
  if (!Object.is(actual, expected)) {
    if (isError(message))
      throw message;

    throw new AssertionError({
      message,
      actual,
      expected,
      operator: 'strictEqual',
      stackStartFn: equal
    });
  }
}

function notEqual(actual, expected, message) {
  if (Object.is(actual, expected)) {
    if (isError(message))
      throw message;

    throw new AssertionError({
      message,
      actual,
      expected,
      operator: 'notStrictEqual',
      stackStartFn: notEqual
    });
  }
}

function fail(message) {
  let generatedMessage = false;

  if (isError(message))
    throw message;

  if (message == null) {
    message = 'Assertion failed.';
    generatedMessage = true;
  }

  throw new AssertionError({
    message,
    actual: false,
    expected: true,
    operator: 'fail',
    generatedMessage,
    stackStartFn: fail
  });
}

function throws(func, expected, message) {
  if (typeof expected === 'string') {
    message = expected;
    expected = undefined;
  }

  let thrown = false;
  let err = null;

  enforce(typeof func === 'function', 'func', 'function');

  try {
    func();
  } catch (e) {
    thrown = true;
    err = e;
  }

  if (!thrown) {
    let generatedMessage = false;

    if (message == null) {
      message = 'Missing expected exception.';
      generatedMessage = true;
    }

    throw new AssertionError({
      message,
      actual: undefined,
      expected,
      operator: 'throws',
      generatedMessage,
      stackStartFn: throws
    });
  }

  if (!testError(err, expected, message, throws))
    throw err;
}

function doesNotThrow(func, expected, message) {
  if (typeof expected === 'string') {
    message = expected;
    expected = undefined;
  }

  let thrown = false;
  let err = null;

  enforce(typeof func === 'function', 'func', 'function');

  try {
    func();
  } catch (e) {
    thrown = true;
    err = e;
  }

  if (!thrown)
    return;

  if (testError(err, expected, message, doesNotThrow)) {
    let generatedMessage = false;

    if (message == null) {
      message = 'Got unwanted exception.';
      generatedMessage = true;
    }

    throw new AssertionError({
      message,
      actual: err,
      expected,
      operator: 'doesNotThrow',
      generatedMessage,
      stackStartFn: doesNotThrow
    });
  }

  throw err;
}

async function rejects(func, expected, message) {
  if (typeof expected === 'string') {
    message = expected;
    expected = undefined;
  }

  let thrown = false;
  let err = null;

  if (typeof func !== 'function')
    enforce(isPromise(func), 'func', 'promise');

  try {
    if (isPromise(func))
      await func;
    else
      await func();
  } catch (e) {
    thrown = true;
    err = e;
  }

  if (!thrown) {
    let generatedMessage = false;

    if (message == null) {
      message = 'Missing expected rejection.';
      generatedMessage = true;
    }

    throw new AssertionError({
      message,
      actual: undefined,
      expected,
      operator: 'rejects',
      generatedMessage,
      stackStartFn: rejects
    });
  }

  if (!testError(err, expected, message, rejects))
    throw err;
}

async function doesNotReject(func, expected, message) {
  if (typeof expected === 'string') {
    message = expected;
    expected = undefined;
  }

  let thrown = false;
  let err = null;

  if (typeof func !== 'function')
    enforce(isPromise(func), 'func', 'promise');

  try {
    if (isPromise(func))
      await func;
    else
      await func();
  } catch (e) {
    thrown = true;
    err = e;
  }

  if (!thrown)
    return;

  if (testError(err, expected, message, doesNotReject)) {
    let generatedMessage = false;

    if (message == null) {
      message = 'Got unwanted rejection.';
      generatedMessage = true;
    }

    throw new AssertionError({
      message,
      actual: undefined,
      expected,
      operator: 'doesNotReject',
      generatedMessage,
      stackStartFn: doesNotReject
    });
  }

  throw err;
}

function ifError(err) {
  if (err != null) {
    let message = 'ifError got unwanted exception: ';

    if (typeof err === 'object' && typeof err.message === 'string') {
      if (err.message.length === 0 && err.constructor)
        message += err.constructor.name;
      else
        message += err.message;
    } else {
      message += stringify(err);
    }

    throw new AssertionError({
      message,
      actual: err,
      expected: null,
      operator: 'ifError',
      generatedMessage: true,
      stackStartFn: ifError
    });
  }
}

function deepEqual(actual, expected, message) {
  if (!isDeepEqual(actual, expected, false)) {
    if (isError(message))
      throw message;

    throw new AssertionError({
      message,
      actual,
      expected,
      operator: 'deepStrictEqual',
      stackStartFn: deepEqual
    });
  }
}

function notDeepEqual(actual, expected, message) {
  if (isDeepEqual(actual, expected, true)) {
    if (isError(message))
      throw message;

    throw new AssertionError({
      message,
      actual,
      expected,
      operator: 'notDeepStrictEqual',
      stackStartFn: notDeepEqual
    });
  }
}

function bufferEqual(actual, expected, enc, message) {
  if (!isEncoding(enc)) {
    message = enc;
    enc = null;
  }

  if (enc == null)
    enc = 'hex';

  expected = bufferize(actual, expected, enc);

  enforce(isBuffer(actual), 'actual', 'buffer');
  enforce(isBuffer(expected), 'expected', 'buffer');

  if (actual !== expected && !actual.equals(expected)) {
    if (isError(message))
      throw message;

    throw new AssertionError({
      message,
      actual: actual.toString(enc),
      expected: expected.toString(enc),
      operator: 'bufferEqual',
      stackStartFn: bufferEqual
    });
  }
}

function notBufferEqual(actual, expected, enc, message) {
  if (!isEncoding(enc)) {
    message = enc;
    enc = null;
  }

  if (enc == null)
    enc = 'hex';

  expected = bufferize(actual, expected, enc);

  enforce(isBuffer(actual), 'actual', 'buffer');
  enforce(isBuffer(expected), 'expected', 'buffer');

  if (actual === expected || actual.equals(expected)) {
    if (isError(message))
      throw message;

    throw new AssertionError({
      message,
      actual: actual.toString(enc),
      expected: expected.toString(enc),
      operator: 'notBufferEqual',
      stackStartFn: notBufferEqual
    });
  }
}

function enforce(value, name, type) {
  if (!value) {
    let msg;

    if (name == null) {
      msg = 'Invalid type for parameter.';
    } else {
      if (type == null)
        msg = `Invalid type for "${name}".`;
      else
        msg = `"${name}" must be a(n) ${type}.`;
    }

    const err = new TypeError(msg);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, enforce);

    throw err;
  }
}

function range(value, name) {
  if (!value) {
    const msg = name != null
      ? `"${name}" is out of range.`
      : 'Parameter is out of range.';

    const err = new RangeError(msg);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, range);

    throw err;
  }
}

/*
 * Stringification
 */

function stringify(value) {
  switch (typeof value) {
    case 'undefined':
      return 'undefined';
    case 'object':
      if (value === null)
        return 'null';
      return `[${objectName(value)}]`;
    case 'boolean':
      return `${value}`;
    case 'number':
      return `${value}`;
    case 'string':
      if (value.length > 80)
        value = `${value.substring(0, 77)}...`;
      return JSON.stringify(value);
    case 'symbol':
      return tryString(value);
    case 'function':
      return `[${funcName(value)}]`;
    case 'bigint':
      return `${value}n`;
    default:
      return `[${typeof value}]`;
  }
}

function toString(value) {
  if (typeof value === 'string')
    return value;

  if (isError(value))
    return tryString(value);

  return stringify(value);
}

function tryString(value) {
  try {
    return String(value);
  } catch (e) {
    return 'Object';
  }
}

/*
 * Error Testing
 */

function testError(err, expected, message, func) {
  if (expected == null)
    return true;

  if (isRegExp(expected))
    return expected.test(err);

  if (typeof expected !== 'function') {
    if (func === doesNotThrow || func === doesNotReject)
      throw new TypeError('"expected" must not be an object.');

    if (typeof expected !== 'object')
      throw new TypeError('"expected" must be an object.');

    let generatedMessage = false;

    if (message == null) {
      const name = func === rejects ? 'rejection' : 'exception';
      message = `Missing expected ${name}.`;
      generatedMessage = true;
    }

    if (err == null || typeof err !== 'object') {
      throw new AssertionError({
        actual: err,
        expected,
        message,
        operator: func.name,
        generatedMessage,
        stackStartFn: func
      });
    }

    const keys = Object.keys(expected);

    if (isError(expected))
      keys.push('name', 'message');

    if (keys.length === 0)
      throw new TypeError('"expected" may not be an empty object.');

    for (const key of keys) {
      const expect = expected[key];
      const value = err[key];

      if (typeof value === 'string'
          && isRegExp(expect)
          && expect.test(value)) {
        continue;
      }

      if ((key in err) && isDeepEqual(value, expect, false))
        continue;

      throw new AssertionError({
        actual: err,
        expected: expected,
        message,
        operator: func.name,
        generatedMessage,
        stackStartFn: func
      });
    }

    return true;
  }

  if (expected.prototype !== undefined && (err instanceof expected))
    return true;

  if (Error.isPrototypeOf(expected))
    return false;

  return expected.call({}, err) === true;
}

/*
 * Comparisons
 */

function isDeepEqual(x, y, fail) {
  try {
    return compare(x, y, null);
  } catch (e) {
    return fail;
  }
}

function compare(a, b, cache) {
  // Primitives.
  if (Object.is(a, b))
    return true;

  if (!isObject(a) || !isObject(b))
    return false;

  // Semi-primitives.
  if (objectString(a) !== objectString(b))
    return false;

  if (Object.getPrototypeOf(a) !== Object.getPrototypeOf(b))
    return false;

  if (isBuffer(a) && isBuffer(b))
    return a.equals(b);

  if (isDate(a))
    return Object.is(a.getTime(), b.getTime());

  if (isRegExp(a)) {
    return a.source === b.source
        && a.global === b.global
        && a.multiline === b.multiline
        && a.lastIndex === b.lastIndex
        && a.ignoreCase === b.ignoreCase;
  }

  if (isError(a)) {
    if (a.message !== b.message)
      return false;
  }

  if (isArrayBuffer(a)) {
    a = new Uint8Array(a);
    b = new Uint8Array(b);
  }

  if (isView(a) && !isBuffer(a)) {
    if (isBuffer(b))
      return false;

    const x = new Uint8Array(a.buffer);
    const y = new Uint8Array(b.buffer);

    if (x.length !== y.length)
      return false;

    for (let i = 0; i < x.length; i++) {
      if (x[i] !== y[i])
        return false;
    }

    return true;
  }

  if (isSet(a)) {
    if (a.size !== b.size)
      return false;

    const keys = new Set([...a, ...b]);

    return keys.size === a.size;
  }

  // Recursive.
  if (!cache) {
    cache = {
      a: new Map(),
      b: new Map(),
      p: 0
    };
  } else {
    const aa = cache.a.get(a);

    if (aa != null) {
      const bb = cache.b.get(b);
      if (bb != null)
        return aa === bb;
    }

    cache.p += 1;
  }

  cache.a.set(a, cache.p);
  cache.b.set(b, cache.p);

  const ret = recurse(a, b, cache);

  cache.a.delete(a);
  cache.b.delete(b);

  return ret;
}

function recurse(a, b, cache) {
  if (isMap(a)) {
    if (a.size !== b.size)
      return false;

    const keys = new Set([...a.keys(), ...b.keys()]);

    if (keys.size !== a.size)
      return false;

    for (const key of keys) {
      if (!compare(a.get(key), b.get(key), cache))
        return false;
    }

    return true;
  }

  if (isArray(a)) {
    if (a.length !== b.length)
      return false;

    for (let i = 0; i < a.length; i++) {
      if (!compare(a[i], b[i], cache))
        return false;
    }

    return true;
  }

  const ak = ownKeys(a);
  const bk = ownKeys(b);

  if (ak.length !== bk.length)
    return false;

  const keys = new Set([...ak, ...bk]);

  if (keys.size !== ak.length)
    return false;

  for (const key of keys) {
    if (!compare(a[key], b[key], cache))
      return false;
  }

  return true;
}

function ownKeys(obj) {
  const keys = Object.keys(obj);

  if (!Object.getOwnPropertySymbols)
    return keys;

  if (!Object.getOwnPropertyDescriptor)
    return keys;

  const symbols = Object.getOwnPropertySymbols(obj);

  for (const symbol of symbols) {
    const desc = Object.getOwnPropertyDescriptor(obj, symbol);

    if (desc && desc.enumerable)
      keys.push(symbol);
  }

  return keys;
}

/*
 * Helpers
 */

function objectString(obj) {
  if (obj === undefined)
    return '[object Undefined]';

  if (obj === null)
    return '[object Null]';

  try {
    return Object.prototype.toString.call(obj);
  } catch (e) {
    return '[object Object]';
  }
}

function objectType(obj) {
  return objectString(obj).slice(8, -1);
}

function objectName(obj) {
  const type = objectType(obj);

  if (obj == null)
    return type;

  if (type !== 'Object' && type !== 'Error')
    return type;

  let ctor, name;

  try {
    ctor = obj.constructor;
  } catch (e) {
    ;
  }

  if (ctor == null)
    return type;

  try {
    name = ctor.name;
  } catch (e) {
    return type;
  }

  if (typeof name !== 'string' || name.length === 0)
    return type;

  return name;
}

function funcName(func) {
  let name;

  try {
    name = func.name;
  } catch (e) {
    ;
  }

  if (typeof name !== 'string' || name.length === 0)
    return 'Function';

  return `Function: ${name}`;
}

function isArray(obj) {
  return Array.isArray(obj);
}

function isArrayBuffer(obj) {
  return obj instanceof ArrayBuffer;
}

function isBuffer(obj) {
  return isObject(obj)
      && typeof obj.writeUInt32LE === 'function'
      && typeof obj.equals === 'function';
}

function isDate(obj) {
  return obj instanceof Date;
}

function isError(obj) {
  return obj instanceof Error;
}

function isMap(obj) {
  return obj instanceof Map;
}

function isObject(obj) {
  return obj && typeof obj === 'object';
}

function isPromise(obj) {
  return obj instanceof Promise;
}

function isRegExp(obj) {
  return obj instanceof RegExp;
}

function isSet(obj) {
  return obj instanceof Set;
}

function isView(obj) {
  return ArrayBuffer.isView(obj);
}

function isEncoding(enc) {
  if (typeof enc !== 'string')
    return false;

  switch (enc) {
    case 'ascii':
    case 'binary':
    case 'base64':
    case 'hex':
    case 'latin1':
    case 'ucs2':
    case 'utf8':
    case 'utf16le':
      return true;
  }

  return false;
}

function bufferize(actual, expected, enc) {
  if (typeof expected === 'string') {
    if (!isBuffer(actual))
      return null;

    const {constructor} = actual;

    if (!constructor || typeof constructor.from !== 'function')
      return null;

    if (!isEncoding(enc))
      return null;

    if (enc === 'hex' && (expected.length & 1))
      return null;

    const raw = constructor.from(expected, enc);

    if (enc === 'hex' && raw.length !== (expected.length >>> 1))
      return null;

    return raw;
  }

  return expected;
}

/*
 * API
 */

assert.AssertionError = AssertionError;
assert.assert = assert;
assert.strict = assert;
assert.ok = assert;
assert.equal = equal;
assert.notEqual = notEqual;
assert.strictEqual = equal;
assert.notStrictEqual = notEqual;
assert.fail = fail;
assert.throws = throws;
assert.doesNotThrow = doesNotThrow;
assert.rejects = rejects;
assert.doesNotReject = doesNotReject;
assert.ifError = ifError;
assert.deepEqual = deepEqual;
assert.notDeepEqual = notDeepEqual;
assert.deepStrictEqual = deepEqual;
assert.notDeepStrictEqual = notDeepEqual;
assert.bufferEqual = bufferEqual;
assert.notBufferEqual = notBufferEqual;
assert.enforce = enforce;
assert.range = range;

/*
 * Expose
 */

module.exports = assert;
}],
[/* 3 */ 'bufio', '/lib/bufio.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * bufio.js - buffer utilities for javascript
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const custom = __node_require__(4 /* './custom' */);
const encoding = __node_require__(5 /* './encoding' */);
const enforce = __node_require__(6 /* './enforce' */);
const EncodingError = __node_require__(7 /* './error' */);
const BufferReader = __node_require__(8 /* './reader' */);
const BufferWriter = __node_require__(9 /* './writer' */);
const StaticWriter = __node_require__(10 /* './staticwriter' */);
const Struct = __node_require__(11 /* './struct' */);

exports.custom = custom;
exports.encoding = encoding;
exports.EncodingError = EncodingError;
exports.BufferReader = BufferReader;
exports.BufferWriter = BufferWriter;
exports.StaticWriter = StaticWriter;
exports.Struct = Struct;

exports.read = function read(data, zeroCopy) {
  return new BufferReader(data, zeroCopy);
};

exports.write = function write(size) {
  return size != null
    ? new StaticWriter(size)
    : new BufferWriter();
};

exports.pool = function pool(size) {
  return StaticWriter.pool(size);
};

function _read(func, size) {
  return function(data, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');

    if (off + size > data.length)
      throw new EncodingError(off, 'Out of bounds read');

    return func(data, off);
  };
}

function _readn(func) {
  return function(data, off, len) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');
    enforce((len >>> 0) === len, 'len', 'integer');

    if (off + len > data.length)
      throw new EncodingError(off, 'Out of bounds read');

    return func(data, off, len);
  };
}

function _readvar(func) {
  return function(data, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');
    return func(data, off);
  };
}

function _write(func, size) {
  return function(data, num, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');

    if (off + size > data.length)
      throw new EncodingError(off, 'Out of bounds write');

    return func(data, num, off);
  };
}

function _writen(func) {
  return function(data, num, off, len) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');
    enforce((len >>> 0) === len, 'len', 'integer');

    if (off + len > data.length)
      throw new EncodingError(off, 'Out of bounds write');

    return func(data, num, off, len);
  };
}

function _writecb(func, size) {
  return function(data, num, off) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce((off >>> 0) === off, 'off', 'integer');

    if (off + size(num) > data.length)
      throw new EncodingError(off, 'Out of bounds write');

    return func(data, num, off);
  };
}

exports.readU = _readn(encoding.readU);
exports.readU64 = _read(encoding.readU64, 8);
exports.readU56 = _read(encoding.readU56, 7);
exports.readU48 = _read(encoding.readU48, 6);
exports.readU40 = _read(encoding.readU40, 5);
exports.readU32 = _read(encoding.readU32, 4);
exports.readU24 = _read(encoding.readU24, 3);
exports.readU16 = _read(encoding.readU16, 2);
exports.readU8 = _read(encoding.readU8, 1);

exports.readUBE = _readn(encoding.readUBE);
exports.readU64BE = _read(encoding.readU64BE, 8);
exports.readU56BE = _read(encoding.readU56BE, 7);
exports.readU48BE = _read(encoding.readU48BE, 6);
exports.readU40BE = _read(encoding.readU40BE, 5);
exports.readU32BE = _read(encoding.readU32BE, 4);
exports.readU24BE = _read(encoding.readU24BE, 3);
exports.readU16BE = _read(encoding.readU16BE, 2);

exports.readI = _readn(encoding.readI);
exports.readI64 = _read(encoding.readI64, 8);
exports.readI56 = _read(encoding.readI56, 7);
exports.readI48 = _read(encoding.readI48, 6);
exports.readI40 = _read(encoding.readI40, 5);
exports.readI32 = _read(encoding.readI32, 4);
exports.readI24 = _read(encoding.readI24, 3);
exports.readI16 = _read(encoding.readI16, 2);
exports.readI8 = _read(encoding.readI8, 1);

exports.readIBE = _readn(encoding.readIBE);
exports.readI64BE = _read(encoding.readI64BE, 8);
exports.readI56BE = _read(encoding.readI56BE, 7);
exports.readI48BE = _read(encoding.readI48BE, 6);
exports.readI40BE = _read(encoding.readI40BE, 5);
exports.readI32BE = _read(encoding.readI32BE, 4);
exports.readI24BE = _read(encoding.readI24BE, 3);
exports.readI16BE = _read(encoding.readI16BE, 2);

exports.readFloat = _read(encoding.readFloat, 4);
exports.readFloatBE = _read(encoding.readFloatBE, 4);
exports.readDouble = _read(encoding.readDouble, 8);
exports.readDoubleBE = _read(encoding.readDoubleBE, 8);

exports.writeU = _writen(encoding.writeU);
exports.writeU64 = _write(encoding.writeU64, 8);
exports.writeU56 = _write(encoding.writeU56, 7);
exports.writeU48 = _write(encoding.writeU48, 6);
exports.writeU40 = _write(encoding.writeU40, 5);
exports.writeU32 = _write(encoding.writeU32, 4);
exports.writeU24 = _write(encoding.writeU24, 3);
exports.writeU16 = _write(encoding.writeU16, 2);
exports.writeU8 = _write(encoding.writeU8, 1);

exports.writeUBE = _writen(encoding.writeUBE);
exports.writeU64BE = _write(encoding.writeU64BE, 8);
exports.writeU56BE = _write(encoding.writeU56BE, 7);
exports.writeU48BE = _write(encoding.writeU48BE, 6);
exports.writeU40BE = _write(encoding.writeU40BE, 5);
exports.writeU32BE = _write(encoding.writeU32BE, 4);
exports.writeU24BE = _write(encoding.writeU24BE, 3);
exports.writeU16BE = _write(encoding.writeU16BE, 2);

exports.writeI = _writen(encoding.writeI);
exports.writeI64 = _write(encoding.writeI64, 8);
exports.writeI56 = _write(encoding.writeI56, 7);
exports.writeI48 = _write(encoding.writeI48, 6);
exports.writeI40 = _write(encoding.writeI40, 5);
exports.writeI32 = _write(encoding.writeI32, 4);
exports.writeI24 = _write(encoding.writeI24, 3);
exports.writeI16 = _write(encoding.writeI16, 2);
exports.writeI8 = _write(encoding.writeI8, 1);

exports.writeIBE = _writen(encoding.writeIBE);
exports.writeI64BE = _write(encoding.writeI64BE, 8);
exports.writeI56BE = _write(encoding.writeI56BE, 7);
exports.writeI48BE = _write(encoding.writeI48BE, 6);
exports.writeI40BE = _write(encoding.writeI40BE, 5);
exports.writeI32BE = _write(encoding.writeI32BE, 4);
exports.writeI24BE = _write(encoding.writeI24BE, 3);
exports.writeI16BE = _write(encoding.writeI16BE, 2);

exports.writeFloat = _write(encoding.writeFloat, 4);
exports.writeFloatBE = _write(encoding.writeFloatBE, 4);
exports.writeDouble = _write(encoding.writeDouble, 8);
exports.writeDoubleBE = _write(encoding.writeDoubleBE, 8);

exports.readVarint = _readvar(encoding.readVarint);
exports.writeVarint = _writecb(encoding.writeVarint, encoding.sizeVarint);
exports.sizeVarint = encoding.sizeVarint;
exports.readVarint2 = _readvar(encoding.readVarint2);
exports.writeVarint2 = _writecb(encoding.writeVarint2, encoding.sizeVarint2);
exports.sizeVarint2 = encoding.sizeVarint2;

exports.sliceBytes = encoding.sliceBytes;
exports.readBytes = encoding.readBytes;
exports.writeBytes = encoding.writeBytes;
exports.readString = encoding.readString;
exports.writeString = encoding.writeString;

exports.realloc = encoding.realloc;
exports.copy = encoding.copy;
exports.concat = encoding.concat;

exports.sizeVarBytes = encoding.sizeVarBytes;
exports.sizeVarlen = encoding.sizeVarlen;
exports.sizeVarString = encoding.sizeVarString;
}],
[/* 4 */ 'bufio', '/lib/custom-browser.js', function(exports, module, __filename, __dirname, __meta) {
'use strict';

exports.custom = 'inspect';
}],
[/* 5 */ 'bufio', '/lib/encoding.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * encoding.js - encoding utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

/* eslint no-implicit-coercion: "off" */

'use strict';

const enforce = __node_require__(6 /* './enforce' */);
const EncodingError = __node_require__(7 /* './error' */);

/*
 * Constants
 */

const HI = 1 / 0x100000000;
const {MAX_SAFE_INTEGER} = Number;
const F32_ARRAY = new Float32Array(1);
const F328_ARRAY = new Uint8Array(F32_ARRAY.buffer);
const F64_ARRAY = new Float64Array(1);
const F648_ARRAY = new Uint8Array(F64_ARRAY.buffer);

F32_ARRAY[0] = -1;

const BIG_ENDIAN = F328_ARRAY[3] === 0;

/*
 * Read Unsigned LE
 */

function readU(data, off, len) {
  switch (len) {
    case 8:
      return readU64(data, off);
    case 7:
      return readU56(data, off);
    case 6:
      return readU48(data, off);
    case 5:
      return readU40(data, off);
    case 4:
      return readU32(data, off);
    case 3:
      return readU24(data, off);
    case 2:
      return readU16(data, off);
    case 1:
      return readU8(data, off);
    default:
      throw new EncodingError(off, 'Invalid read length');
  }
}

function readU64(data, off) {
  const hi = readU32(data, off + 4);
  const lo = readU32(data, off);

  check((hi & 0xffe00000) === 0, off, 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readU56(data, off) {
  const hi = readU24(data, off + 4);
  const lo = readU32(data, off);

  check((hi & 0xffe00000) === 0, off, 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readU48(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off++] * 0x1000000
        + data[off++] * 0x100000000
        + data[off] * 0x10000000000);
}

function readU40(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off++] * 0x1000000
        + data[off] * 0x100000000);
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

function readU24(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off] * 0x10000);
}

function readU16(data, off) {
  return data[off++] + data[off] * 0x100;
}

function readU8(data, off) {
  return data[off];
}

/*
 * Read Unsigned BE
 */

function readUBE(data, off, len) {
  switch (len) {
    case 8:
      return readU64BE(data, off);
    case 7:
      return readU56BE(data, off);
    case 6:
      return readU48BE(data, off);
    case 5:
      return readU40BE(data, off);
    case 4:
      return readU32BE(data, off);
    case 3:
      return readU24BE(data, off);
    case 2:
      return readU16BE(data, off);
    case 1:
      return readU8(data, off);
    default:
      throw new EncodingError(off, 'Invalid read length');
  }
}

function readU64BE(data, off) {
  const hi = readU32BE(data, off);
  const lo = readU32BE(data, off + 4);

  check((hi & 0xffe00000) === 0, off, 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readU56BE(data, off) {
  const hi = readU24BE(data, off);
  const lo = readU32BE(data, off + 3);

  check((hi & 0xffe00000) === 0, off, 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readU48BE(data, off) {
  return (data[off++] * 0x10000000000
        + data[off++] * 0x100000000
        + data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readU40BE(data, off) {
  return (data[off++] * 0x100000000
        + data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readU32BE(data, off) {
  return (data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readU24BE(data, off) {
  return (data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readU16BE(data, off) {
  return data[off++] * 0x100 + data[off];
}

/*
 * Read Signed LE
 */

function readI(data, off, len) {
  switch (len) {
    case 8:
      return readI64(data, off);
    case 7:
      return readI56(data, off);
    case 6:
      return readI48(data, off);
    case 5:
      return readI40(data, off);
    case 4:
      return readI32(data, off);
    case 3:
      return readI24(data, off);
    case 2:
      return readI16(data, off);
    case 1:
      return readI8(data, off);
    default:
      throw new EncodingError(off, 'Invalid read length');
  }
}

function readI64(data, off) {
  const hi = readI32(data, off + 4);
  const lo = readU32(data, off);

  check(isSafe(hi, lo), 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readI56(data, off) {
  const hi = readI24(data, off + 4);
  const lo = readU32(data, off);

  check(isSafe(hi, lo), 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readI48(data, off) {
  const val = data[off + 4] + data[off + 5] * 0x100;

  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000
        + (val | (val & 0x8000) * 0x1fffe) * 0x100000000);
}

function readI40(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off++] * 0x1000000
        + (data[off] | (data[off] & 0x80) * 0x1fffffe) * 0x100000000);
}

function readI32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + (data[off] << 24));
}

function readI24(data, off) {
  const val = (data[off++]
             + data[off++] * 0x100
             + data[off] * 0x10000);

  return val | (val & 0x800000) * 0x1fe;
}

function readI16(data, off) {
  const val = data[off++] + data[off] * 0x100;
  return val | (val & 0x8000) * 0x1fffe;
}

function readI8(data, off) {
  const val = data[off];
  return val | (val & 0x80) * 0x1fffffe;
}

/*
 * Read Signed BE
 */

function readIBE(data, off, len) {
  switch (len) {
    case 8:
      return readI64BE(data, off);
    case 7:
      return readI56BE(data, off);
    case 6:
      return readI48BE(data, off);
    case 5:
      return readI40BE(data, off);
    case 4:
      return readI32BE(data, off);
    case 3:
      return readI24BE(data, off);
    case 2:
      return readI16BE(data, off);
    case 1:
      return readI8(data, off);
    default:
      throw new EncodingError(off, 'Invalid read length');
  }
}

function readI64BE(data, off) {
  const hi = readI32BE(data, off);
  const lo = readU32BE(data, off + 4);

  check(isSafe(hi, lo), 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readI56BE(data, off) {
  const hi = readI24BE(data, off);
  const lo = readU32BE(data, off + 3);

  check(isSafe(hi, lo), 'Number exceeds 2^53-1');

  return hi * 0x100000000 + lo;
}

function readI48BE(data, off) {
  const val = data[off++] * 0x100 + data[off++];

  return ((val | (val & 0x8000) * 0x1fffe) * 0x100000000
        + data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readI40BE(data, off) {
  const val = data[off++];

  return ((val | (val & 0x80) * 0x1fffffe) * 0x100000000
        + data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readI32BE(data, off) {
  return ((data[off++] << 24)
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function readI24BE(data, off) {
  const val = (data[off++] * 0x10000
             + data[off++] * 0x100
             + data[off]);

  return val | (val & 0x800000) * 0x1fe;
}

function readI16BE(data, off) {
  const val = data[off++] * 0x100 + data[off];
  return val | (val & 0x8000) * 0x1fffe;
}

/*
 * Read Float
 */

function _readFloatBackwards(data, off) {
  F328_ARRAY[3] = data[off++];
  F328_ARRAY[2] = data[off++];
  F328_ARRAY[1] = data[off++];
  F328_ARRAY[0] = data[off];
  return F32_ARRAY[0];
}

function _readFloatForwards(data, off) {
  F328_ARRAY[0] = data[off++];
  F328_ARRAY[1] = data[off++];
  F328_ARRAY[2] = data[off++];
  F328_ARRAY[3] = data[off];
  return F32_ARRAY[0];
}

function _readDoubleBackwards(data, off) {
  F648_ARRAY[7] = data[off++];
  F648_ARRAY[6] = data[off++];
  F648_ARRAY[5] = data[off++];
  F648_ARRAY[4] = data[off++];
  F648_ARRAY[3] = data[off++];
  F648_ARRAY[2] = data[off++];
  F648_ARRAY[1] = data[off++];
  F648_ARRAY[0] = data[off];
  return F64_ARRAY[0];
}

function _readDoubleForwards(data, off) {
  F648_ARRAY[0] = data[off++];
  F648_ARRAY[1] = data[off++];
  F648_ARRAY[2] = data[off++];
  F648_ARRAY[3] = data[off++];
  F648_ARRAY[4] = data[off++];
  F648_ARRAY[5] = data[off++];
  F648_ARRAY[6] = data[off++];
  F648_ARRAY[7] = data[off];
  return F64_ARRAY[0];
}

const readFloat = BIG_ENDIAN ? _readFloatBackwards : _readFloatForwards;
const readFloatBE = BIG_ENDIAN ? _readFloatForwards : _readFloatBackwards;
const readDouble = BIG_ENDIAN ? _readDoubleBackwards : _readDoubleForwards;
const readDoubleBE = BIG_ENDIAN ? _readDoubleForwards : _readDoubleBackwards;

/*
 * Write Unsigned LE
 */

function writeU(dst, num, off, len) {
  switch (len) {
    case 8:
      return writeU64(dst, num, off);
    case 7:
      return writeU56(dst, num, off);
    case 6:
      return writeU48(dst, num, off);
    case 5:
      return writeU40(dst, num, off);
    case 4:
      return writeU32(dst, num, off);
    case 3:
      return writeU24(dst, num, off);
    case 2:
      return writeU16(dst, num, off);
    case 1:
      return writeU8(dst, num, off);
    default:
      throw new EncodingError(off, 'Invalid write length');
  }
}

function writeU64(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');
  return write64(dst, num, off, false);
}

function writeU56(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');
  return write56(dst, num, off, false);
}

function writeU48(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  const hi = (num * HI) | 0;

  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  dst[off++] = hi;
  dst[off++] = hi >>> 8;

  return off;
}

function writeU40(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  const hi = (num * HI) | 0;

  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  dst[off++] = hi;

  return off;
}

function writeU32(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;

  return off;
}

function writeU24(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;

  return off;
}

function writeU16(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off++] = num;
  dst[off++] = num >>> 8;

  return off;
}

function writeU8(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off] = num;

  return off + 1;
}

/*
 * Write Unsigned BE
 */

function writeUBE(dst, num, off, len) {
  switch (len) {
    case 8:
      return writeU64BE(dst, num, off);
    case 7:
      return writeU56BE(dst, num, off);
    case 6:
      return writeU48BE(dst, num, off);
    case 5:
      return writeU40BE(dst, num, off);
    case 4:
      return writeU32BE(dst, num, off);
    case 3:
      return writeU24BE(dst, num, off);
    case 2:
      return writeU16BE(dst, num, off);
    case 1:
      return writeU8(dst, num, off);
    default:
      throw new EncodingError(off, 'Invalid write length');
  }
}

function writeU64BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');
  return write64(dst, num, off, true);
}

function writeU56BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');
  return write56(dst, num, off, true);
}

function writeU48BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  const hi = (num * HI) | 0;

  dst[off++] = hi >>> 8;
  dst[off++] = hi;
  dst[off + 3] = num;
  num >>>= 8;
  dst[off + 2] = num;
  num >>>= 8;
  dst[off + 1] = num;
  num >>>= 8;
  dst[off] = num;

  return off + 4;
}

function writeU40BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  const hi = (num * HI) | 0;

  dst[off++] = hi;
  dst[off + 3] = num;
  num >>>= 8;
  dst[off + 2] = num;
  num >>>= 8;
  dst[off + 1] = num;
  num >>>= 8;
  dst[off] = num;

  return off + 4;
}

function writeU32BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off + 3] = num;
  num >>>= 8;
  dst[off + 2] = num;
  num >>>= 8;
  dst[off + 1] = num;
  num >>>= 8;
  dst[off] = num;

  return off + 4;
}

function writeU24BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off + 2] = num;
  num >>>= 8;
  dst[off + 1] = num;
  num >>>= 8;
  dst[off] = num;

  return off + 3;
}

function writeU16BE(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  dst[off++] = num >>> 8;
  dst[off++] = num;

  return off;
}

/*
 * Write Signed LE
 */

function writeI(dst, num, off, len) {
  switch (len) {
    case 8:
      return writeU64(dst, num, off);
    case 7:
      return writeU56(dst, num, off);
    case 6:
      return writeU48(dst, num, off);
    case 5:
      return writeU40(dst, num, off);
    case 4:
      return writeU24(dst, num, off);
    case 3:
      return writeU32(dst, num, off);
    case 2:
      return writeU16(dst, num, off);
    case 1:
      return writeU8(dst, num, off);
    default:
      throw new EncodingError(off, 'Invalid write length');
  }
}

function writeI64(dst, num, off) {
  return writeU64(dst, num, off);
}

function writeI56(dst, num, off) {
  return writeU56(dst, num, off);
}

function writeI48(dst, num, off) {
  return writeU48(dst, num, off);
}

function writeI40(dst, num, off) {
  return writeU40(dst, num, off);
}

function writeI32(dst, num, off) {
  return writeU32(dst, num, off);
}

function writeI24(dst, num, off) {
  return writeU24(dst, num, off);
}

function writeI16(dst, num, off) {
  return writeU16(dst, num, off);
}

function writeI8(dst, num, off) {
  return writeU8(dst, num, off);
}

/*
 * Write Signed BE
 */

function writeIBE(dst, num, off, len) {
  switch (len) {
    case 8:
      return writeU64BE(dst, num, off);
    case 7:
      return writeU56BE(dst, num, off);
    case 6:
      return writeU48BE(dst, num, off);
    case 5:
      return writeU40BE(dst, num, off);
    case 4:
      return writeU32BE(dst, num, off);
    case 3:
      return writeU24BE(dst, num, off);
    case 2:
      return writeU16BE(dst, num, off);
    case 1:
      return writeU8(dst, num, off);
    default:
      throw new EncodingError(off, 'Invalid write length');
  }
}

function writeI64BE(dst, num, off) {
  return writeU64BE(dst, num, off);
}

function writeI56BE(dst, num, off) {
  return writeU56BE(dst, num, off);
}

function writeI48BE(dst, num, off) {
  return writeU48BE(dst, num, off);
}

function writeI40BE(dst, num, off) {
  return writeU40BE(dst, num, off);
}

function writeI32BE(dst, num, off) {
  return writeU32BE(dst, num, off);
}

function writeI24BE(dst, num, off) {
  return writeU24BE(dst, num, off);
}

function writeI16BE(dst, num, off) {
  return writeU16BE(dst, num, off);
}

function _writeDoubleForwards(dst, num, off) {
  enforce(isNumber(num), 'num', 'number');

  F64_ARRAY[0] = num;

  dst[off++] = F648_ARRAY[0];
  dst[off++] = F648_ARRAY[1];
  dst[off++] = F648_ARRAY[2];
  dst[off++] = F648_ARRAY[3];
  dst[off++] = F648_ARRAY[4];
  dst[off++] = F648_ARRAY[5];
  dst[off++] = F648_ARRAY[6];
  dst[off++] = F648_ARRAY[7];

  return off;
}

function _writeDoubleBackwards(dst, num, off) {
  enforce(isNumber(num), 'num', 'number');

  F64_ARRAY[0] = num;

  dst[off++] = F648_ARRAY[7];
  dst[off++] = F648_ARRAY[6];
  dst[off++] = F648_ARRAY[5];
  dst[off++] = F648_ARRAY[4];
  dst[off++] = F648_ARRAY[3];
  dst[off++] = F648_ARRAY[2];
  dst[off++] = F648_ARRAY[1];
  dst[off++] = F648_ARRAY[0];

  return off;
}

function _writeFloatForwards(dst, num, off) {
  enforce(isNumber(num), 'num', 'number');

  F32_ARRAY[0] = num;

  dst[off++] = F328_ARRAY[0];
  dst[off++] = F328_ARRAY[1];
  dst[off++] = F328_ARRAY[2];
  dst[off++] = F328_ARRAY[3];

  return off;
}

function _writeFloatBackwards(dst, num, off) {
  enforce(isNumber(num), 'num', 'number');

  F32_ARRAY[0] = num;

  dst[off++] = F328_ARRAY[3];
  dst[off++] = F328_ARRAY[2];
  dst[off++] = F328_ARRAY[1];
  dst[off++] = F328_ARRAY[0];

  return off;
}

const writeFloat = BIG_ENDIAN ? _writeFloatBackwards : _writeFloatForwards;
const writeFloatBE = BIG_ENDIAN ? _writeFloatForwards : _writeFloatBackwards;
const writeDouble = BIG_ENDIAN ? _writeDoubleBackwards : _writeDoubleForwards;
const writeDoubleBE = BIG_ENDIAN ? _writeDoubleForwards : _writeDoubleBackwards;

/*
 * Varints
 */

function readVarint(data, off) {
  let value, size;

  checkRead(off < data.length, off);

  switch (data[off]) {
    case 0xff:
      size = 9;
      checkRead(off + size <= data.length, off);
      value = readU64(data, off + 1);
      check(value > 0xffffffff, off, 'Non-canonical varint');
      break;
    case 0xfe:
      size = 5;
      checkRead(off + size <= data.length, off);
      value = readU32(data, off + 1);
      check(value > 0xffff, off, 'Non-canonical varint');
      break;
    case 0xfd:
      size = 3;
      checkRead(off + size <= data.length, off);
      value = readU16(data, off + 1);
      check(value >= 0xfd, off, 'Non-canonical varint');
      break;
    default:
      size = 1;
      value = data[off];
      break;
  }

  return new Varint(size, value);
}

function writeVarint(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  if (num < 0xfd) {
    dst[off++] = num;
    return off;
  }

  if (num <= 0xffff) {
    dst[off++] = 0xfd;
    return writeU16(dst, num, off);
  }

  if (num <= 0xffffffff) {
    dst[off++] = 0xfe;
    return writeU32(dst, num, off);
  }

  dst[off++] = 0xff;

  return writeU64(dst, num, off);
}

function sizeVarint(num) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  if (num < 0xfd)
    return 1;

  if (num <= 0xffff)
    return 3;

  if (num <= 0xffffffff)
    return 5;

  return 9;
}

function readVarint2(data, off) {
  let num = 0;
  let size = 0;

  for (;;) {
    checkRead(off < data.length, off);

    const ch = data[off++];

    size += 1;

    // Number.MAX_SAFE_INTEGER >>> 7
    check(num <= 0x3fffffffffff - (ch & 0x7f), off, 'Number exceeds 2^53-1');

    // num = (num << 7) | (ch & 0x7f);
    num = (num * 0x80) + (ch & 0x7f);

    if ((ch & 0x80) === 0)
      break;

    check(num !== MAX_SAFE_INTEGER, off, 'Number exceeds 2^53-1');
    num += 1;
  }

  return new Varint(size, num);
}

function writeVarint2(dst, num, off) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  const tmp = [];

  let len = 0;

  for (;;) {
    tmp[len] = (num & 0x7f) | (len ? 0x80 : 0x00);

    if (num <= 0x7f)
      break;

    // num = (num >>> 7) - 1;
    num = ((num - (num % 0x80)) / 0x80) - 1;
    len += 1;
  }

  checkRead(off + len + 1 <= dst.length, off);

  do {
    dst[off++] = tmp[len];
  } while (len--);

  return off;
}

function sizeVarint2(num) {
  enforce(Number.isSafeInteger(num), 'num', 'integer');

  let size = 0;

  for (;;) {
    size += 1;

    if (num <= 0x7f)
      break;

    // num = (num >>> 7) - 1;
    num = ((num - (num % 0x80)) / 0x80) - 1;
  }

  return size;
}

/*
 * Bytes
 */

function sliceBytes(data, off, size) {
  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  enforce((off >>> 0) === off, 'off', 'integer');
  enforce((size >>> 0) === size, 'size', 'integer');

  if (off + size > data.length)
    throw new EncodingError(off, 'Out of bounds read');

  return data.slice(off, off + size);
}

function readBytes(data, off, size) {
  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  enforce((off >>> 0) === off, 'off', 'integer');
  enforce((size >>> 0) === size, 'size', 'integer');

  if (off + size > data.length)
    throw new EncodingError(off, 'Out of bounds read');

  const buf = Buffer.allocUnsafeSlow(size);

  data.copy(buf, 0, off, off + size);

  return buf;
}

function writeBytes(data, value, off) {
  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  enforce(Buffer.isBuffer(value), 'value', 'buffer');
  enforce((off >>> 0) === off, 'off', 'integer');

  if (off + value.length > data.length)
    throw new EncodingError(off, 'Out of bounds write');

  return value.copy(data, off, 0, value.length);
}

function readString(data, off, size, enc) {
  if (enc == null)
    enc = 'binary';

  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  enforce((off >>> 0) === off, 'off', 'integer');
  enforce((size >>> 0) === size, 'size', 'integer');
  enforce(typeof enc === 'string', 'enc', 'string');

  if (off + size > data.length)
    throw new EncodingError(off, 'Out of bounds read');

  return data.toString(enc, off, off + size);
}

function writeString(data, str, off, enc) {
  if (enc == null)
    enc = 'binary';

  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  enforce(typeof str === 'string', 'str', 'string');
  enforce((off >>> 0) === off, 'off', 'integer');
  enforce(typeof enc === 'string', 'enc', 'string');

  if (str.length === 0)
    return 0;

  const size = Buffer.byteLength(str, enc);

  if (off + size > data.length)
    throw new EncodingError(off, 'Out of bounds write');

  return data.write(str, off, enc);
}

function realloc(data, size) {
  enforce(Buffer.isBuffer(data), 'data', 'buffer');

  const buf = Buffer.allocUnsafeSlow(size);

  data.copy(buf, 0);

  return buf;
}

function copy(data) {
  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  return realloc(data, data.length);
}

function concat(a, b) {
  enforce(Buffer.isBuffer(a), 'a', 'buffer');
  enforce(Buffer.isBuffer(b), 'b', 'buffer');

  const size = a.length + b.length;
  const buf = Buffer.allocUnsafeSlow(size);

  a.copy(buf, 0);
  b.copy(buf, a.length);

  return buf;
}

/*
 * Size Helpers
 */

function sizeVarBytes(data) {
  enforce(Buffer.isBuffer(data), 'data', 'buffer');
  return sizeVarint(data.length) + data.length;
}

function sizeVarlen(len) {
  return sizeVarint(len) + len;
}

function sizeVarString(str, enc) {
  if (enc == null)
    enc = 'binary';

  enforce(typeof str === 'string', 'str', 'string');
  enforce(typeof enc === 'string', 'enc', 'string');

  if (str.length === 0)
    return 1;

  const len = Buffer.byteLength(str, enc);

  return sizeVarint(len) + len;
}

/*
 * Helpers
 */

function isSafe(hi, lo) {
  if (hi < 0) {
    hi = ~hi;
    if (lo === 0)
      hi += 1;
  }

  return (hi & 0xffe00000) === 0;
}

function write64(dst, num, off, be) {
  let neg = false;

  if (num < 0) {
    num = -num;
    neg = true;
  }

  let hi = (num * HI) | 0;
  let lo = num | 0;

  if (neg) {
    if (lo === 0) {
      hi = (~hi + 1) | 0;
    } else {
      hi = ~hi;
      lo = ~lo + 1;
    }
  }

  if (be) {
    off = writeI32BE(dst, hi, off);
    off = writeI32BE(dst, lo, off);
  } else {
    off = writeI32(dst, lo, off);
    off = writeI32(dst, hi, off);
  }

  return off;
}

function write56(dst, num, off, be) {
  let neg = false;

  if (num < 0) {
    num = -num;
    neg = true;
  }

  let hi = (num * HI) | 0;
  let lo = num | 0;

  if (neg) {
    if (lo === 0) {
      hi = (~hi + 1) | 0;
    } else {
      hi = ~hi;
      lo = ~lo + 1;
    }
  }

  if (be) {
    off = writeI24BE(dst, hi, off);
    off = writeI32BE(dst, lo, off);
  } else {
    off = writeI32(dst, lo, off);
    off = writeI24(dst, hi, off);
  }

  return off;
}

class Varint {
  constructor(size, value) {
    this.size = size;
    this.value = value;
  }
}

function isNumber(num) {
  return typeof num === 'number' && isFinite(num);
}

function checkRead(value, offset) {
  if (!value)
    throw new EncodingError(offset, 'Out of bounds read', checkRead);
}

function check(value, offset, reason) {
  if (!value)
    throw new EncodingError(offset, reason, check);
}

/*
 * Expose
 */

exports.readU = readU;
exports.readU64 = readU64;
exports.readU56 = readU56;
exports.readU48 = readU48;
exports.readU40 = readU40;
exports.readU32 = readU32;
exports.readU24 = readU24;
exports.readU16 = readU16;
exports.readU8 = readU8;

exports.readUBE = readUBE;
exports.readU64BE = readU64BE;
exports.readU56BE = readU56BE;
exports.readU48BE = readU48BE;
exports.readU40BE = readU40BE;
exports.readU32BE = readU32BE;
exports.readU24BE = readU24BE;
exports.readU16BE = readU16BE;

exports.readI = readI;
exports.readI64 = readI64;
exports.readI56 = readI56;
exports.readI48 = readI48;
exports.readI40 = readI40;
exports.readI32 = readI32;
exports.readI24 = readI24;
exports.readI16 = readI16;
exports.readI8 = readI8;

exports.readIBE = readIBE;
exports.readI64BE = readI64BE;
exports.readI56BE = readI56BE;
exports.readI48BE = readI48BE;
exports.readI40BE = readI40BE;
exports.readI32BE = readI32BE;
exports.readI24BE = readI24BE;
exports.readI16BE = readI16BE;

exports.readFloat = readFloat;
exports.readFloatBE = readFloatBE;
exports.readDouble = readDouble;
exports.readDoubleBE = readDoubleBE;

exports.writeU = writeU;
exports.writeU64 = writeU64;
exports.writeU56 = writeU56;
exports.writeU48 = writeU48;
exports.writeU40 = writeU40;
exports.writeU32 = writeU32;
exports.writeU24 = writeU24;
exports.writeU16 = writeU16;
exports.writeU8 = writeU8;

exports.writeUBE = writeUBE;
exports.writeU64BE = writeU64BE;
exports.writeU56BE = writeU56BE;
exports.writeU48BE = writeU48BE;
exports.writeU40BE = writeU40BE;
exports.writeU32BE = writeU32BE;
exports.writeU24BE = writeU24BE;
exports.writeU16BE = writeU16BE;

exports.writeI = writeI;
exports.writeI64 = writeI64;
exports.writeI56 = writeI56;
exports.writeI48 = writeI48;
exports.writeI40 = writeI40;
exports.writeI32 = writeI32;
exports.writeI24 = writeI24;
exports.writeI16 = writeI16;
exports.writeI8 = writeI8;

exports.writeIBE = writeIBE;
exports.writeI64BE = writeI64BE;
exports.writeI56BE = writeI56BE;
exports.writeI48BE = writeI48BE;
exports.writeI40BE = writeI40BE;
exports.writeI32BE = writeI32BE;
exports.writeI24BE = writeI24BE;
exports.writeI16BE = writeI16BE;

exports.writeFloat = writeFloat;
exports.writeFloatBE = writeFloatBE;
exports.writeDouble = writeDouble;
exports.writeDoubleBE = writeDoubleBE;

exports.readVarint = readVarint;
exports.writeVarint = writeVarint;
exports.sizeVarint = sizeVarint;
exports.readVarint2 = readVarint2;
exports.writeVarint2 = writeVarint2;
exports.sizeVarint2 = sizeVarint2;

exports.sliceBytes = sliceBytes;
exports.readBytes = readBytes;
exports.writeBytes = writeBytes;
exports.readString = readString;
exports.writeString = writeString;

exports.realloc = realloc;
exports.copy = copy;
exports.concat = concat;

exports.sizeVarBytes = sizeVarBytes;
exports.sizeVarlen = sizeVarlen;
exports.sizeVarString = sizeVarString;
}],
[/* 6 */ 'bufio', '/lib/enforce.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * enforce.js - type enforcement for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/*
 * Enforce
 */

function enforce(value, name, type) {
  if (!value) {
    const err = new TypeError(`'${name}' must be a(n) ${type}.`);

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, enforce);

    throw err;
  }
}

/*
 * Expose
 */

module.exports = enforce;
}],
[/* 7 */ 'bufio', '/lib/error.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * error.js - encoding error for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * Encoding Error
 * @extends {Error}
 */

class EncodingError extends Error {
  /**
   * Create an encoding error.
   * @constructor
   * @param {Number} offset
   * @param {String} reason
   */

  constructor(offset, reason, start) {
    super();

    this.type = 'EncodingError';
    this.name = 'EncodingError';
    this.code = 'ERR_ENCODING';
    this.message = `${reason} (offset=${offset}).`;

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, start || EncodingError);
  }
}

/*
 * Expose
 */

module.exports = EncodingError;
}],
[/* 8 */ 'bufio', '/lib/reader.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * reader.js - buffer reader for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = __node_require__(6 /* './enforce' */);
const encoding = __node_require__(5 /* './encoding' */);
const EncodingError = __node_require__(7 /* './error' */);

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/**
 * Buffer Reader
 */

class BufferReader {
  /**
   * Create a buffer reader.
   * @constructor
   * @param {Buffer} data
   * @param {Boolean?} zeroCopy - Do not reallocate buffers when
   * slicing. Note that this can lead to memory leaks if not used
   * carefully.
   */

  constructor(data, zeroCopy = false) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    enforce(typeof zeroCopy === 'boolean', 'zeroCopy', 'boolean');

    this.data = data;
    this.offset = 0;
    this.zeroCopy = zeroCopy;
    this.stack = [];
  }

  /**
   * Assertion.
   * @param {Number} size
   */

  check(size) {
    if (this.offset + size > this.data.length)
      throw new EncodingError(this.offset, 'Out of bounds read', this.check);
  }

  /**
   * Get total size of passed-in Buffer.
   * @returns {Buffer}
   */

  getSize() {
    return this.data.length;
  }

  /**
   * Calculate number of bytes left to read.
   * @returns {Number}
   */

  left() {
    this.check(0);
    return this.data.length - this.offset;
  }

  /**
   * Seek to a position to read from by offset.
   * @param {Number} off - Offset (positive or negative).
   */

  seek(off) {
    enforce(Number.isSafeInteger(off), 'off', 'integer');

    if (this.offset + off < 0)
      throw new EncodingError(this.offset, 'Out of bounds read');

    this.check(off);
    this.offset += off;

    return this;
  }

  /**
   * Mark the current starting position.
   */

  start() {
    this.stack.push(this.offset);
    return this.offset;
  }

  /**
   * Stop reading. Pop the start position off the stack
   * and calculate the size of the data read.
   * @returns {Number} Size.
   * @throws on empty stack.
   */

  end() {
    if (this.stack.length === 0)
      throw new Error('Cannot end without a stack item.');

    const start = this.stack.pop();

    return this.offset - start;
  }

  /**
   * Stop reading. Pop the start position off the stack
   * and return the data read.
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer} Data read.
   * @throws on empty stack.
   */

  endData(zeroCopy = false) {
    enforce(typeof zeroCopy === 'boolean', 'zeroCopy', 'boolean');

    if (this.stack.length === 0)
      throw new Error('Cannot end without a stack item.');

    const start = this.stack.pop();
    const end = this.offset;
    const size = end - start;
    const data = this.data;

    if (size === data.length)
      return data;

    if (this.zeroCopy || zeroCopy)
      return data.slice(start, end);

    const ret = Buffer.allocUnsafeSlow(size);

    data.copy(ret, 0, start, end);

    return ret;
  }

  /**
   * Destroy the reader. Remove references to the data.
   */

  destroy() {
    this.data = EMPTY;
    this.offset = 0;
    this.stack.length = 0;
    return this;
  }

  /**
   * Read uint8.
   * @returns {Number}
   */

  readU8() {
    this.check(1);

    const ret = this.data[this.offset];

    this.offset += 1;

    return ret;
  }

  /**
   * Read uint16le.
   * @returns {Number}
   */

  readU16() {
    this.check(2);

    const ret = encoding.readU16(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read uint16be.
   * @returns {Number}
   */

  readU16BE() {
    this.check(2);

    const ret = encoding.readU16BE(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read uint24le.
   * @returns {Number}
   */

  readU24() {
    this.check(3);

    const ret = encoding.readU24(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read uint24be.
   * @returns {Number}
   */

  readU24BE() {
    this.check(3);

    const ret = encoding.readU24BE(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read uint32le.
   * @returns {Number}
   */

  readU32() {
    this.check(4);

    const ret = encoding.readU32(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read uint32be.
   * @returns {Number}
   */

  readU32BE() {
    this.check(4);

    const ret = encoding.readU32BE(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read uint40le.
   * @returns {Number}
   */

  readU40() {
    this.check(5);

    const ret = encoding.readU40(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read uint40be.
   * @returns {Number}
   */

  readU40BE() {
    this.check(5);

    const ret = encoding.readU40BE(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read uint48le.
   * @returns {Number}
   */

  readU48() {
    this.check(6);

    const ret = encoding.readU48(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read uint48be.
   * @returns {Number}
   */

  readU48BE() {
    this.check(6);

    const ret = encoding.readU48BE(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read uint56le.
   * @returns {Number}
   */

  readU56() {
    this.check(7);

    const ret = encoding.readU56(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read uint56be.
   * @returns {Number}
   */

  readU56BE() {
    this.check(7);

    const ret = encoding.readU56BE(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read uint64le as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readU64() {
    this.check(8);

    const ret = encoding.readU64(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read uint64be as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readU64BE() {
    this.check(8);

    const ret = encoding.readU64BE(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read int8.
   * @returns {Number}
   */

  readI8() {
    this.check(1);

    const ret = encoding.readI8(this.data, this.offset);

    this.offset += 1;

    return ret;
  }

  /**
   * Read int16le.
   * @returns {Number}
   */

  readI16() {
    this.check(2);

    const ret = encoding.readI16(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read int16be.
   * @returns {Number}
   */

  readI16BE() {
    this.check(2);

    const ret = encoding.readI16BE(this.data, this.offset);

    this.offset += 2;

    return ret;
  }

  /**
   * Read int24le.
   * @returns {Number}
   */

  readI24() {
    this.check(3);

    const ret = encoding.readI24(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read int24be.
   * @returns {Number}
   */

  readI24BE() {
    this.check(3);

    const ret = encoding.readI24BE(this.data, this.offset);

    this.offset += 3;

    return ret;
  }

  /**
   * Read int32le.
   * @returns {Number}
   */

  readI32() {
    this.check(4);

    const ret = encoding.readI32(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read int32be.
   * @returns {Number}
   */

  readI32BE() {
    this.check(4);

    const ret = encoding.readI32BE(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read int40le.
   * @returns {Number}
   */

  readI40() {
    this.check(5);

    const ret = encoding.readI40(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read int40be.
   * @returns {Number}
   */

  readI40BE() {
    this.check(5);

    const ret = encoding.readI40BE(this.data, this.offset);

    this.offset += 5;

    return ret;
  }

  /**
   * Read int48le.
   * @returns {Number}
   */

  readI48() {
    this.check(6);

    const ret = encoding.readI48(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read int48be.
   * @returns {Number}
   */

  readI48BE() {
    this.check(6);

    const ret = encoding.readI48BE(this.data, this.offset);

    this.offset += 6;

    return ret;
  }

  /**
   * Read int56le.
   * @returns {Number}
   */

  readI56() {
    this.check(7);

    const ret = encoding.readI56(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read int56be.
   * @returns {Number}
   */

  readI56BE() {
    this.check(7);

    const ret = encoding.readI56BE(this.data, this.offset);

    this.offset += 7;

    return ret;
  }

  /**
   * Read int64le as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readI64() {
    this.check(8);

    const ret = encoding.readI64(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read int64be as a js number.
   * @returns {Number}
   * @throws on num > MAX_SAFE_INTEGER
   */

  readI64BE() {
    this.check(8);

    const ret = encoding.readI64BE(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read float le.
   * @returns {Number}
   */

  readFloat() {
    this.check(4);

    const ret = encoding.readFloat(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read float be.
   * @returns {Number}
   */

  readFloatBE() {
    this.check(4);

    const ret = encoding.readFloatBE(this.data, this.offset);

    this.offset += 4;

    return ret;
  }

  /**
   * Read double float le.
   * @returns {Number}
   */

  readDouble() {
    this.check(8);

    const ret = encoding.readDouble(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read double float be.
   * @returns {Number}
   */

  readDoubleBE() {
    this.check(8);

    const ret = encoding.readDoubleBE(this.data, this.offset);

    this.offset += 8;

    return ret;
  }

  /**
   * Read a varint.
   * @returns {Number}
   */

  readVarint() {
    const {size, value} = encoding.readVarint(this.data, this.offset);

    this.offset += size;

    return value;
  }

  /**
   * Read a varint (type 2).
   * @returns {Number}
   */

  readVarint2() {
    const {size, value} = encoding.readVarint2(this.data, this.offset);

    this.offset += size;

    return value;
  }

  /**
   * Read N bytes (will do a fast slice if zero copy).
   * @param {Number} size
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer}
   */

  readBytes(size, zeroCopy = false) {
    enforce((size >>> 0) === size, 'size', 'integer');
    enforce(typeof zeroCopy === 'boolean', 'zeroCopy', 'boolean');

    this.check(size);

    let ret;

    if (this.zeroCopy || zeroCopy) {
      ret = this.data.slice(this.offset, this.offset + size);
    } else {
      ret = Buffer.allocUnsafeSlow(size);
      this.data.copy(ret, 0, this.offset, this.offset + size);
    }

    this.offset += size;

    return ret;
  }

  /**
   * Read a varint number of bytes (will do a fast slice if zero copy).
   * @param {Bolean?} zeroCopy - Do a fast buffer
   * slice instead of allocating a new buffer (warning:
   * may cause memory leaks if not used with care).
   * @returns {Buffer}
   */

  readVarBytes(zeroCopy = false) {
    return this.readBytes(this.readVarint(), zeroCopy);
  }

  /**
   * Slice N bytes and create a child reader.
   * @param {Number} size
   * @returns {BufferReader}
   */

  readChild(size) {
    enforce((size >>> 0) === size, 'size', 'integer');

    this.check(size);

    const data = this.data.slice(0, this.offset + size);
    const br = new this.constructor(data);

    br.offset = this.offset;

    this.offset += size;

    return br;
  }

  /**
   * Read a string.
   * @param {Number} size
   * @param {String} enc - Any buffer-supported encoding.
   * @returns {String}
   */

  readString(size, enc) {
    if (enc == null)
      enc = 'binary';

    enforce((size >>> 0) === size, 'size', 'integer');
    enforce(typeof enc === 'string', 'enc', 'string');

    this.check(size);

    const ret = this.data.toString(enc, this.offset, this.offset + size);

    this.offset += size;

    return ret;
  }

  /**
   * Read a 32-byte hash.
   * @param {String} enc - `"hex"` or `null`.
   * @returns {Hash|Buffer}
   */

  readHash(enc) {
    if (enc)
      return this.readString(32, enc);
    return this.readBytes(32);
  }

  /**
   * Read string of a varint length.
   * @param {String} enc - Any buffer-supported encoding.
   * @param {Number?} limit - Size limit.
   * @returns {String}
   */

  readVarString(enc, limit = 0) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof enc === 'string', 'enc', 'string');
    enforce((limit >>> 0) === limit, 'limit', 'integer');

    const size = this.readVarint();

    if (limit !== 0 && size > limit)
      throw new EncodingError(this.offset, 'String exceeds limit');

    return this.readString(size, enc);
  }

  /**
   * Read a null-terminated string.
   * @param {String} enc - Any buffer-supported encoding.
   * @returns {String}
   */

  readNullString(enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof enc === 'string', 'enc', 'string');

    let i = this.offset;

    for (; i < this.data.length; i++) {
      if (this.data[i] === 0)
        break;
    }

    if (i === this.data.length)
      throw new EncodingError(this.offset, 'No NUL terminator');

    const ret = this.readString(i - this.offset, enc);

    this.offset = i + 1;

    return ret;
  }

  /**
   * Create a checksum from the last start position.
   * @param {Function} hash
   * @returns {Number} Checksum.
   */

  createChecksum(hash) {
    if (!hash || typeof hash.digest !== 'function')
      enforce(typeof hash === 'function', 'hash', 'function');

    let start = 0;

    if (this.stack.length > 0)
      start = this.stack[this.stack.length - 1];

    const data = this.data.slice(start, this.offset);
    const raw = hash.digest ? hash.digest(data) : hash(data);

    return encoding.readU32(raw, 0);
  }

  /**
   * Verify a 4-byte checksum against a calculated checksum.
   * @param {Function} hash
   * @returns {Number} checksum
   * @throws on bad checksum
   */

  verifyChecksum(hash) {
    const checksum = this.createChecksum(hash);
    const expect = this.readU32();

    if (checksum !== expect)
      throw new EncodingError(this.offset, 'Checksum mismatch');

    return checksum;
  }
}

/*
 * Expose
 */

module.exports = BufferReader;
}],
[/* 9 */ 'bufio', '/lib/writer.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * writer.js - buffer writer for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = __node_require__(6 /* './enforce' */);
const encoding = __node_require__(5 /* './encoding' */);
const EncodingError = __node_require__(7 /* './error' */);

/*
 * Constants
 */

const SEEK = 0;
const U8 = 1;
const U16 = 2;
const U16BE = 3;
const U24 = 4;
const U24BE = 5;
const U32 = 6;
const U32BE = 7;
const U40 = 8;
const U40BE = 9;
const U48 = 10;
const U48BE = 11;
const U56 = 12;
const U56BE = 13;
const U64 = 14;
const U64BE = 15;
const I8 = 16;
const I16 = 17;
const I16BE = 18;
const I24 = 19;
const I24BE = 20;
const I32 = 21;
const I32BE = 22;
const I40 = 23;
const I40BE = 24;
const I48 = 25;
const I48BE = 26;
const I56 = 27;
const I56BE = 28;
const I64 = 29;
const I64BE = 30;
const FL = 31;
const FLBE = 32;
const DBL = 33;
const DBLBE = 34;
const VARINT = 35;
const VARINT2 = 36;
const BYTES = 37;
const STR = 38;
const CHECKSUM = 39;
const FILL = 40;

/**
 * Buffer Writer
 */

class BufferWriter {
  /**
   * Create a buffer writer.
   * @constructor
   */

  constructor() {
    this.ops = [];
    this.offset = 0;
  }

  /**
   * Allocate and render the final buffer.
   * @returns {Buffer} Rendered buffer.
   */

  render() {
    const data = Buffer.allocUnsafeSlow(this.offset);

    let off = 0;

    for (const op of this.ops) {
      switch (op.type) {
        case SEEK:
          off += op.value;
          break;
        case U8:
          off = encoding.writeU8(data, op.value, off);
          break;
        case U16:
          off = encoding.writeU16(data, op.value, off);
          break;
        case U16BE:
          off = encoding.writeU16BE(data, op.value, off);
          break;
        case U24:
          off = encoding.writeU24(data, op.value, off);
          break;
        case U24BE:
          off = encoding.writeU24BE(data, op.value, off);
          break;
        case U32:
          off = encoding.writeU32(data, op.value, off);
          break;
        case U32BE:
          off = encoding.writeU32BE(data, op.value, off);
          break;
        case U40:
          off = encoding.writeU40(data, op.value, off);
          break;
        case U40BE:
          off = encoding.writeU40BE(data, op.value, off);
          break;
        case U48:
          off = encoding.writeU48(data, op.value, off);
          break;
        case U48BE:
          off = encoding.writeU48BE(data, op.value, off);
          break;
        case U56:
          off = encoding.writeU56(data, op.value, off);
          break;
        case U56BE:
          off = encoding.writeU56BE(data, op.value, off);
          break;
        case U64:
          off = encoding.writeU64(data, op.value, off);
          break;
        case U64BE:
          off = encoding.writeU64BE(data, op.value, off);
          break;
        case I8:
          off = encoding.writeI8(data, op.value, off);
          break;
        case I16:
          off = encoding.writeI16(data, op.value, off);
          break;
        case I16BE:
          off = encoding.writeI16BE(data, op.value, off);
          break;
        case I24:
          off = encoding.writeI24(data, op.value, off);
          break;
        case I24BE:
          off = encoding.writeI24BE(data, op.value, off);
          break;
        case I32:
          off = encoding.writeI32(data, op.value, off);
          break;
        case I32BE:
          off = encoding.writeI32BE(data, op.value, off);
          break;
        case I40:
          off = encoding.writeI40(data, op.value, off);
          break;
        case I40BE:
          off = encoding.writeI40BE(data, op.value, off);
          break;
        case I48:
          off = encoding.writeI48(data, op.value, off);
          break;
        case I48BE:
          off = encoding.writeI48BE(data, op.value, off);
          break;
        case I56:
          off = encoding.writeI56(data, op.value, off);
          break;
        case I56BE:
          off = encoding.writeI56BE(data, op.value, off);
          break;
        case I64:
          off = encoding.writeI64(data, op.value, off);
          break;
        case I64BE:
          off = encoding.writeI64BE(data, op.value, off);
          break;
        case FL:
          off = encoding.writeFloat(data, op.value, off);
          break;
        case FLBE:
          off = encoding.writeFloatBE(data, op.value, off);
          break;
        case DBL:
          off = encoding.writeDouble(data, op.value, off);
          break;
        case DBLBE:
          off = encoding.writeDoubleBE(data, op.value, off);
          break;
        case VARINT:
          off = encoding.writeVarint(data, op.value, off);
          break;
        case VARINT2:
          off = encoding.writeVarint2(data, op.value, off);
          break;
        case BYTES:
          off += op.data.copy(data, off);
          break;
        case STR:
          off += data.write(op.value, off, op.enc);
          break;
        case CHECKSUM:
          off += op.func(data.slice(0, off)).copy(data, off, 0, 4);
          break;
        case FILL:
          data.fill(op.value, off, off + op.size);
          off += op.size;
          break;
        default:
          throw new Error('Invalid type.');
      }
    }

    if (off !== data.length)
      throw new EncodingError(off, 'Out of bounds write');

    this.destroy();

    return data;
  }

  /**
   * Get size of data written so far.
   * @returns {Number}
   */

  getSize() {
    return this.offset;
  }

  /**
   * Seek to relative offset.
   * @param {Number} offset
   */

  seek(off) {
    enforce(Number.isSafeInteger(off), 'off', 'integer');

    if (this.offset + off < 0)
      throw new EncodingError(this.offset, 'Out of bounds write');

    this.offset += off;
    this.ops.push(new NumberOp(SEEK, off));

    return this;
  }

  /**
   * Destroy the buffer writer. Remove references to `ops`.
   */

  destroy() {
    this.ops.length = 0;
    this.offset = 0;
    return this;
  }

  /**
   * Write uint8.
   * @param {Number} value
   */

  writeU8(value) {
    this.offset += 1;
    this.ops.push(new NumberOp(U8, value));
    return this;
  }

  /**
   * Write uint16le.
   * @param {Number} value
   */

  writeU16(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(U16, value));
    return this;
  }

  /**
   * Write uint16be.
   * @param {Number} value
   */

  writeU16BE(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(U16BE, value));
    return this;
  }

  /**
   * Write uint24le.
   * @param {Number} value
   */

  writeU24(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(U24, value));
    return this;
  }

  /**
   * Write uint24be.
   * @param {Number} value
   */

  writeU24BE(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(U24BE, value));
    return this;
  }

  /**
   * Write uint32le.
   * @param {Number} value
   */

  writeU32(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(U32, value));
    return this;
  }

  /**
   * Write uint32be.
   * @param {Number} value
   */

  writeU32BE(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(U32BE, value));
    return this;
  }

  /**
   * Write uint40le.
   * @param {Number} value
   */

  writeU40(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(U40, value));
    return this;
  }

  /**
   * Write uint40be.
   * @param {Number} value
   */

  writeU40BE(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(U40BE, value));
    return this;
  }

  /**
   * Write uint48le.
   * @param {Number} value
   */

  writeU48(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(U48, value));
    return this;
  }

  /**
   * Write uint48be.
   * @param {Number} value
   */

  writeU48BE(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(U48BE, value));
    return this;
  }

  /**
   * Write uint56le.
   * @param {Number} value
   */

  writeU56(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(U56, value));
    return this;
  }

  /**
   * Write uint56be.
   * @param {Number} value
   */

  writeU56BE(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(U56BE, value));
    return this;
  }

  /**
   * Write uint64le.
   * @param {Number} value
   */

  writeU64(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(U64, value));
    return this;
  }

  /**
   * Write uint64be.
   * @param {Number} value
   */

  writeU64BE(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(U64BE, value));
    return this;
  }

  /**
   * Write int8.
   * @param {Number} value
   */

  writeI8(value) {
    this.offset += 1;
    this.ops.push(new NumberOp(I8, value));
    return this;
  }

  /**
   * Write int16le.
   * @param {Number} value
   */

  writeI16(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(I16, value));
    return this;
  }

  /**
   * Write int16be.
   * @param {Number} value
   */

  writeI16BE(value) {
    this.offset += 2;
    this.ops.push(new NumberOp(I16BE, value));
    return this;
  }

  /**
   * Write int24le.
   * @param {Number} value
   */

  writeI24(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(I24, value));
    return this;
  }

  /**
   * Write int24be.
   * @param {Number} value
   */

  writeI24BE(value) {
    this.offset += 3;
    this.ops.push(new NumberOp(I24BE, value));
    return this;
  }

  /**
   * Write int32le.
   * @param {Number} value
   */

  writeI32(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(I32, value));
    return this;
  }

  /**
   * Write int32be.
   * @param {Number} value
   */

  writeI32BE(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(I32BE, value));
    return this;
  }

  /**
   * Write int40le.
   * @param {Number} value
   */

  writeI40(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(I40, value));
    return this;
  }

  /**
   * Write int40be.
   * @param {Number} value
   */

  writeI40BE(value) {
    this.offset += 5;
    this.ops.push(new NumberOp(I40BE, value));
    return this;
  }

  /**
   * Write int48le.
   * @param {Number} value
   */

  writeI48(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(I48, value));
    return this;
  }

  /**
   * Write int48be.
   * @param {Number} value
   */

  writeI48BE(value) {
    this.offset += 6;
    this.ops.push(new NumberOp(I48BE, value));
    return this;
  }

  /**
   * Write int56le.
   * @param {Number} value
   */

  writeI56(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(I56, value));
    return this;
  }

  /**
   * Write int56be.
   * @param {Number} value
   */

  writeI56BE(value) {
    this.offset += 7;
    this.ops.push(new NumberOp(I56BE, value));
    return this;
  }

  /**
   * Write int64le.
   * @param {Number} value
   */

  writeI64(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(I64, value));
    return this;
  }

  /**
   * Write int64be.
   * @param {Number} value
   */

  writeI64BE(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(I64BE, value));
    return this;
  }

  /**
   * Write float le.
   * @param {Number} value
   */

  writeFloat(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(FL, value));
    return this;
  }

  /**
   * Write float be.
   * @param {Number} value
   */

  writeFloatBE(value) {
    this.offset += 4;
    this.ops.push(new NumberOp(FLBE, value));
    return this;
  }

  /**
   * Write double le.
   * @param {Number} value
   */

  writeDouble(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(DBL, value));
    return this;
  }

  /**
   * Write double be.
   * @param {Number} value
   */

  writeDoubleBE(value) {
    this.offset += 8;
    this.ops.push(new NumberOp(DBLBE, value));
    return this;
  }

  /**
   * Write a varint.
   * @param {Number} value
   */

  writeVarint(value) {
    this.offset += encoding.sizeVarint(value);
    this.ops.push(new NumberOp(VARINT, value));
    return this;
  }

  /**
   * Write a varint (type 2).
   * @param {Number} value
   */

  writeVarint2(value) {
    this.offset += encoding.sizeVarint2(value);
    this.ops.push(new NumberOp(VARINT2, value));
    return this;
  }

  /**
   * Write bytes.
   * @param {Buffer} value
   */

  writeBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    if (value.length === 0)
      return this;

    this.offset += value.length;
    this.ops.push(new BufferOp(BYTES, value));

    return this;
  }

  /**
   * Write bytes with a varint length before them.
   * @param {Buffer} value
   */

  writeVarBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    this.offset += encoding.sizeVarint(value.length);
    this.ops.push(new NumberOp(VARINT, value.length));

    if (value.length === 0)
      return this;

    this.offset += value.length;
    this.ops.push(new BufferOp(BYTES, value));

    return this;
  }

  /**
   * Copy bytes.
   * @param {Buffer} value
   * @param {Number} start
   * @param {Number} end
   */

  copy(value, start, end) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');
    enforce((start >>> 0) === start, 'start', 'integer');
    enforce((end >>> 0) === end, 'end', 'integer');
    enforce(end >= start, 'start', 'integer');

    const buf = value.slice(start, end);

    this.writeBytes(buf);

    return this;
  }

  /**
   * Write string to buffer.
   * @param {String} value
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0)
      return this;

    this.offset += Buffer.byteLength(value, enc);
    this.ops.push(new StringOp(STR, value, enc));

    return this;
  }

  /**
   * Write a 32 byte hash.
   * @param {Hash} value
   */

  writeHash(value) {
    if (typeof value !== 'string') {
      enforce(Buffer.isBuffer(value), 'value', 'buffer');
      enforce(value.length === 32, 'value', '32-byte hash');
      this.writeBytes(value);
      return this;
    }

    enforce(value.length === 64, 'value', '32-byte hash');

    this.writeString(value, 'hex');

    return this;
  }

  /**
   * Write a string with a varint length before it.
   * @param {String}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeVarString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0) {
      this.ops.push(new NumberOp(VARINT, 0));
      return this;
    }

    const size = Buffer.byteLength(value, enc);

    this.offset += encoding.sizeVarint(size);
    this.offset += size;

    this.ops.push(new NumberOp(VARINT, size));
    this.ops.push(new StringOp(STR, value, enc));

    return this;
  }

  /**
   * Write a null-terminated string.
   * @param {String|Buffer}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeNullString(value, enc) {
    this.writeString(value, enc);
    this.writeU8(0);
    return this;
  }

  /**
   * Calculate and write a checksum for the data written so far.
   * @param {Function} hash
   */

  writeChecksum(hash) {
    if (hash && typeof hash.digest === 'function')
      hash = hash.digest.bind(hash);

    enforce(typeof hash === 'function', 'hash', 'function');

    this.offset += 4;
    this.ops.push(new FunctionOp(CHECKSUM, hash));

    return this;
  }

  /**
   * Fill N bytes with value.
   * @param {Number} value
   * @param {Number} size
   */

  fill(value, size) {
    enforce((value & 0xff) === value, 'value', 'byte');
    enforce((size >>> 0) === size, 'size', 'integer');

    if (size === 0)
      return this;

    this.offset += size;
    this.ops.push(new FillOp(FILL, value, size));

    return this;
  }
}

/*
 * Helpers
 */

class WriteOp {
  constructor(type) {
    this.type = type;
  }
}

class NumberOp extends WriteOp {
  constructor(type, value) {
    super(type);
    this.value = value;
  }
}

class BufferOp extends WriteOp {
  constructor(type, data) {
    super(type);
    this.data = data;
  }
}

class StringOp extends WriteOp {
  constructor(type, value, enc) {
    super(type);
    this.value = value;
    this.enc = enc;
  }
}

class FunctionOp extends WriteOp {
  constructor(type, func) {
    super(type);
    this.func = func;
  }
}

class FillOp extends WriteOp {
  constructor(type, value, size) {
    super(type);
    this.value = value;
    this.size = size;
  }
}

/*
 * Expose
 */

module.exports = BufferWriter;
}],
[/* 10 */ 'bufio', '/lib/staticwriter.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * staticwriter.js - buffer writer for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = __node_require__(6 /* './enforce' */);
const encoding = __node_require__(5 /* './encoding' */);
const EncodingError = __node_require__(7 /* './error' */);

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const POOL_SIZE = 100 << 10;

let POOL = null;

/**
 * Statically Allocated Writer
 */

class StaticWriter {
  /**
   * Statically allocated buffer writer.
   * @constructor
   * @param {Number|Buffer} options
   */

  constructor(options) {
    this.data = EMPTY;
    this.offset = 0;

    if (options != null)
      this.init(options);
  }

  /**
   * Assertion.
   * @param {Number} size
   */

  check(size) {
    if (this.offset + size > this.data.length)
      throw new EncodingError(this.offset, 'Out of bounds write', this.check);
  }

  /**
   * Initialize options.
   * @param {Object} options
   */

  init(options) {
    if (Buffer.isBuffer(options)) {
      this.data = options;
      this.offset = 0;
      return this;
    }

    enforce((options >>> 0) === options, 'size', 'integer');

    this.data = Buffer.allocUnsafeSlow(options);
    this.offset = 0;

    return this;
  }

  /**
   * Allocate writer from preallocated 100kb pool.
   * @param {Number} size
   * @returns {StaticWriter}
   */

  static pool(size) {
    enforce((size >>> 0) === size, 'size', 'integer');

    if (size <= POOL_SIZE) {
      if (!POOL)
        POOL = Buffer.allocUnsafeSlow(POOL_SIZE);

      const bw = new StaticWriter();

      bw.data = POOL.slice(0, size);

      return bw;
    }

    return new StaticWriter(size);
  }

  /**
   * Allocate and render the final buffer.
   * @returns {Buffer} Rendered buffer.
   */

  render() {
    const {data, offset} = this;

    if (offset !== data.length)
      throw new EncodingError(offset, 'Out of bounds write');

    this.destroy();

    return data;
  }

  /**
   * Slice the final buffer at written offset.
   * @returns {Buffer} Rendered buffer.
   */

  slice() {
    const {data, offset} = this;

    if (offset > data.length)
      throw new EncodingError(offset, 'Out of bounds write');

    this.destroy();

    return data.slice(0, offset);
  }

  /**
   * Get size of data written so far.
   * @returns {Number}
   */

  getSize() {
    return this.offset;
  }

  /**
   * Seek to relative offset.
   * @param {Number} off
   */

  seek(off) {
    enforce(Number.isSafeInteger(off), 'off', 'integer');

    if (this.offset + off < 0)
      throw new EncodingError(this.offset, 'Out of bounds write');

    this.check(off);
    this.offset += off;

    return this;
  }

  /**
   * Destroy the buffer writer.
   */

  destroy() {
    this.data = EMPTY;
    this.offset = 0;
    return this;
  }

  /**
   * Write uint8.
   * @param {Number} value
   */

  writeU8(value) {
    this.check(1);
    this.offset = encoding.writeU8(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint16le.
   * @param {Number} value
   */

  writeU16(value) {
    this.check(2);
    this.offset = encoding.writeU16(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint16be.
   * @param {Number} value
   */

  writeU16BE(value) {
    this.check(2);
    this.offset = encoding.writeU16BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint24le.
   * @param {Number} value
   */

  writeU24(value) {
    this.check(3);
    this.offset = encoding.writeU24(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint24be.
   * @param {Number} value
   */

  writeU24BE(value) {
    this.check(3);
    this.offset = encoding.writeU24BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint32le.
   * @param {Number} value
   */

  writeU32(value) {
    this.check(4);
    this.offset = encoding.writeU32(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint32be.
   * @param {Number} value
   */

  writeU32BE(value) {
    this.check(4);
    this.offset = encoding.writeU32BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint40le.
   * @param {Number} value
   */

  writeU40(value) {
    this.check(5);
    this.offset = encoding.writeU40(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint40be.
   * @param {Number} value
   */

  writeU40BE(value) {
    this.check(5);
    this.offset = encoding.writeU40BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint48le.
   * @param {Number} value
   */

  writeU48(value) {
    this.check(6);
    this.offset = encoding.writeU48(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint48be.
   * @param {Number} value
   */

  writeU48BE(value) {
    this.check(6);
    this.offset = encoding.writeU48BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint56le.
   * @param {Number} value
   */

  writeU56(value) {
    this.check(7);
    this.offset = encoding.writeU56(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint56be.
   * @param {Number} value
   */

  writeU56BE(value) {
    this.check(7);
    this.offset = encoding.writeU56BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint64le.
   * @param {Number} value
   */

  writeU64(value) {
    this.check(8);
    this.offset = encoding.writeU64(this.data, value, this.offset);
    return this;
  }

  /**
   * Write uint64be.
   * @param {Number} value
   */

  writeU64BE(value) {
    this.check(8);
    this.offset = encoding.writeU64BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int8.
   * @param {Number} value
   */

  writeI8(value) {
    this.check(1);
    this.offset = encoding.writeI8(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int16le.
   * @param {Number} value
   */

  writeI16(value) {
    this.check(2);
    this.offset = encoding.writeI16(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int16be.
   * @param {Number} value
   */

  writeI16BE(value) {
    this.check(2);
    this.offset = encoding.writeI16BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int24le.
   * @param {Number} value
   */

  writeI24(value) {
    this.check(3);
    this.offset = encoding.writeI24(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int24be.
   * @param {Number} value
   */

  writeI24BE(value) {
    this.check(3);
    this.offset = encoding.writeI24BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int32le.
   * @param {Number} value
   */

  writeI32(value) {
    this.check(4);
    this.offset = encoding.writeI32(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int32be.
   * @param {Number} value
   */

  writeI32BE(value) {
    this.check(4);
    this.offset = encoding.writeI32BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int40le.
   * @param {Number} value
   */

  writeI40(value) {
    this.check(5);
    this.offset = encoding.writeI40(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int40be.
   * @param {Number} value
   */

  writeI40BE(value) {
    this.check(5);
    this.offset = encoding.writeI40BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int48le.
   * @param {Number} value
   */

  writeI48(value) {
    this.check(6);
    this.offset = encoding.writeI48(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int48be.
   * @param {Number} value
   */

  writeI48BE(value) {
    this.check(6);
    this.offset = encoding.writeI48BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int56le.
   * @param {Number} value
   */

  writeI56(value) {
    this.check(7);
    this.offset = encoding.writeI56(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int56be.
   * @param {Number} value
   */

  writeI56BE(value) {
    this.check(7);
    this.offset = encoding.writeI56BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int64le.
   * @param {Number} value
   */

  writeI64(value) {
    this.check(8);
    this.offset = encoding.writeI64(this.data, value, this.offset);
    return this;
  }

  /**
   * Write int64be.
   * @param {Number} value
   */

  writeI64BE(value) {
    this.check(8);
    this.offset = encoding.writeI64BE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write float le.
   * @param {Number} value
   */

  writeFloat(value) {
    this.check(4);
    this.offset = encoding.writeFloat(this.data, value, this.offset);
    return this;
  }

  /**
   * Write float be.
   * @param {Number} value
   */

  writeFloatBE(value) {
    this.check(4);
    this.offset = encoding.writeFloatBE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write double le.
   * @param {Number} value
   */

  writeDouble(value) {
    this.check(8);
    this.offset = encoding.writeDouble(this.data, value, this.offset);
    return this;
  }

  /**
   * Write double be.
   * @param {Number} value
   */

  writeDoubleBE(value) {
    this.check(8);
    this.offset = encoding.writeDoubleBE(this.data, value, this.offset);
    return this;
  }

  /**
   * Write a varint.
   * @param {Number} value
   */

  writeVarint(value) {
    this.offset = encoding.writeVarint(this.data, value, this.offset);
    return this;
  }

  /**
   * Write a varint (type 2).
   * @param {Number} value
   */

  writeVarint2(value) {
    this.offset = encoding.writeVarint2(this.data, value, this.offset);
    return this;
  }

  /**
   * Write bytes.
   * @param {Buffer} value
   */

  writeBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    this.check(value.length);
    this.offset += value.copy(this.data, this.offset);

    return this;
  }

  /**
   * Write bytes with a varint length before them.
   * @param {Buffer} value
   */

  writeVarBytes(value) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');

    this.writeVarint(value.length);
    this.writeBytes(value);

    return this;
  }

  /**
   * Copy bytes.
   * @param {Buffer} value
   * @param {Number} start
   * @param {Number} end
   */

  copy(value, start, end) {
    enforce(Buffer.isBuffer(value), 'value', 'buffer');
    enforce((start >>> 0) === start, 'start', 'integer');
    enforce((end >>> 0) === end, 'end', 'integer');
    enforce(end >= start, 'start', 'integer');

    this.check(end - start);
    this.offset += value.copy(this.data, this.offset, start, end);

    return this;
  }

  /**
   * Write string to buffer.
   * @param {String} value
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0)
      return this;

    const size = Buffer.byteLength(value, enc);

    this.check(size);

    this.offset += this.data.write(value, this.offset, enc);

    return this;
  }

  /**
   * Write a 32 byte hash.
   * @param {Hash} value
   */

  writeHash(value) {
    if (typeof value !== 'string') {
      enforce(Buffer.isBuffer(value), 'value', 'buffer');
      enforce(value.length === 32, 'value', '32-byte hash');
      this.writeBytes(value);
      return this;
    }

    enforce(value.length === 64, 'value', '32-byte hash');

    this.check(32);
    this.offset += this.data.write(value, this.offset, 'hex');

    return this;
  }

  /**
   * Write a string with a varint length before it.
   * @param {String}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeVarString(value, enc) {
    if (enc == null)
      enc = 'binary';

    enforce(typeof value === 'string', 'value', 'string');
    enforce(typeof enc === 'string', 'enc', 'string');

    if (value.length === 0) {
      this.writeVarint(0);
      return this;
    }

    const size = Buffer.byteLength(value, enc);

    this.writeVarint(size);
    this.check(size);
    this.offset += this.data.write(value, this.offset, enc);

    return this;
  }

  /**
   * Write a null-terminated string.
   * @param {String|Buffer}
   * @param {String?} enc - Any buffer-supported encoding.
   */

  writeNullString(value, enc) {
    this.writeString(value, enc);
    this.writeU8(0);
    return this;
  }

  /**
   * Calculate and write a checksum for the data written so far.
   * @param {Function} hash
   */

  writeChecksum(hash) {
    if (!hash || typeof hash.digest !== 'function')
      enforce(typeof hash === 'function', 'hash', 'function');

    this.check(4);

    const data = this.data.slice(0, this.offset);
    const raw = hash.digest ? hash.digest(data) : hash(data);

    raw.copy(this.data, this.offset, 0, 4);

    this.offset += 4;

    return this;
  }

  /**
   * Fill N bytes with value.
   * @param {Number} value
   * @param {Number} size
   */

  fill(value, size) {
    enforce((value & 0xff) === value, 'value', 'byte');
    enforce((size >>> 0) === size, 'size', 'integer');

    this.check(size);

    this.data.fill(value, this.offset, this.offset + size);
    this.offset += size;

    return this;
  }
}

/*
 * Expose
 */

module.exports = StaticWriter;
}],
[/* 11 */ 'bufio', '/lib/struct.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * struct.js - struct object for bcoin
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = __node_require__(6 /* './enforce' */);
const BufferReader = __node_require__(8 /* './reader' */);
const BufferWriter = __node_require__(9 /* './writer' */);
const StaticWriter = __node_require__(10 /* './staticwriter' */);
const {custom} = __node_require__(4 /* './custom' */);

/**
 * Struct
 */

class Struct {
  constructor() {}

  inject(obj) {
    enforce(obj instanceof this.constructor, 'obj', 'struct');
    return this.decode(obj.encode());
  }

  clone() {
    const copy = new this.constructor();
    return copy.inject(this);
  }

  /*
   * Bindable
   */

  getSize(extra) {
    return -1;
  }

  write(bw, extra) {
    return bw;
  }

  read(br, extra) {
    return this;
  }

  toString() {
    return Object.prototype.toString.call(this);
  }

  fromString(str, extra) {
    return this;
  }

  getJSON() {
    return this;
  }

  fromJSON(json, extra) {
    return this;
  }

  fromOptions(options, extra) {
    return this;
  }

  from(options, extra) {
    return this.fromOptions(options, extra);
  }

  format() {
    return this.getJSON();
  }

  /*
   * API
   */

  encode(extra) {
    const size = this.getSize(extra);
    const bw = size === -1
      ? new BufferWriter()
      : new StaticWriter(size);

    this.write(bw, extra);

    return bw.render();
  }

  decode(data, extra) {
    const br = new BufferReader(data);

    this.read(br, extra);

    return this;
  }

  toHex(extra) {
    return this.encode(extra).toString('hex');
  }

  fromHex(str, extra) {
    enforce(typeof str === 'string', 'str', 'string');

    const size = str.length >>> 1;
    const data = Buffer.from(str, 'hex');

    if (data.length !== size)
      throw new Error('Invalid hex string.');

    return this.decode(data, extra);
  }

  toBase64(extra) {
    return this.encode(extra).toString('base64');
  }

  fromBase64(str, extra) {
    enforce(typeof str === 'string', 'str', 'string');

    const data = Buffer.from(str, 'base64');

    if (str.length > size64(data.length))
      throw new Error('Invalid base64 string.');

    return this.decode(data, extra);
  }

  toJSON() {
    return this.getJSON();
  }

  [custom]() {
    return this.format();
  }

  /*
   * Static API
   */

  static read(br, extra) {
    return new this().read(br, extra);
  }

  static decode(data, extra) {
    return new this().decode(data, extra);
  }

  static fromHex(str, extra) {
    return new this().fromHex(str, extra);
  }

  static fromBase64(str, extra) {
    return new this().fromBase64(str, extra);
  }

  static fromString(str, extra) {
    return new this().fromString(str, extra);
  }

  static fromJSON(json, extra) {
    return new this().fromJSON(json, extra);
  }

  static fromOptions(options, extra) {
    return new this().fromOptions(options, extra);
  }

  static from(options, extra) {
    return new this().from(options, extra);
  }

  /*
   * Aliases
   */

  toWriter(bw, extra) {
    return this.write(bw, extra);
  }

  fromReader(br, extra) {
    return this.read(br, extra);
  }

  toRaw(extra) {
    return this.encode(extra);
  }

  fromRaw(data, extra) {
    return this.decode(data, extra);
  }

  /*
   * Static Aliases
   */

  static fromReader(br, extra) {
    return this.read(br, extra);
  }

  static fromRaw(data, extra) {
    return this.decode(data, extra);
  }
}

/*
 * Helpers
 */

function size64(size) {
  const expect = ((4 * size / 3) + 3) & ~3;
  return expect >>> 0;
}

/*
 * Expose
 */

module.exports = Struct;
}],
[/* 12 */ 'bcrypto', '/lib/encoding/base58-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(13 /* '../js/base58' */);
}],
[/* 13 */ 'bcrypto', '/lib/js/base58.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * base58.js - base58 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on bitcoin/bitcoin:
 *   Copyright (c) 2009-2019, The Bitcoin Core Developers (MIT License).
 *   Copyright (c) 2009-2019, The Bitcoin Developers (MIT License).
 *   https://github.com/bitcoin/bitcoin
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);

/*
 * Constants
 */

const CHARSET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,
   7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15,
  16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29,
  30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39,
  40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54,
  55, 56, 57, -1, -1, -1, -1, -1
];

const pool = Buffer.alloc(128);

/**
 * Encode a base58 string.
 * @param {Buffer} data
 * @returns {String}
 */

function encode(data) {
  assert(Buffer.isBuffer(data));

  let zeroes = 0;
  let i = 0;

  for (; i < data.length; i++) {
    if (data[i] !== 0)
      break;

    zeroes += 1;
  }

  const size = (((data.length - zeroes) * 138 / 100) | 0) + 1;
  const b58 = size <= 128 ? pool.fill(0) : Buffer.alloc(size);

  let length = 0;

  for (; i < data.length; i++) {
    let carry = data[i];
    let j = 0;

    for (let k = size - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;

      carry += b58[k] * 256;
      b58[k] = carry % 58;
      carry = (carry / 58) | 0;
    }

    assert(carry === 0);

    length = j;
  }

  i = size - length;

  while (i < size && b58[i] === 0)
    i += 1;

  let str = '';

  for (let j = 0; j < zeroes; j++)
    str += '1';

  while (i < size)
    str += CHARSET[b58[i++]];

  return str;
}

/**
 * Decode a base58 string.
 * @param {String} str
 * @returns {Buffer}
 * @throws on non-base58 character.
 */

function decode(str) {
  assert(typeof str === 'string');

  let zeroes = 0;
  let i = 0;

  for (; i < str.length; i++) {
    if (str[i] !== '1')
      break;

    zeroes += 1;
  }

  const size = ((str.length * 733) / 1000 | 0) + 1;
  const b256 = size <= 128 ? pool.fill(0) : Buffer.alloc(size);

  let length = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      throw new Error('Invalid base58 string.');

    const val = TABLE[ch];

    if (val === -1)
      throw new Error('Invalid base58 string.');

    let carry = val;
    let j = 0;

    for (let k = size - 1; k >= 0; k--, j++) {
      if (carry === 0 && j >= length)
        break;

      carry += b256[k] * 58;
      b256[k] = carry;
      carry >>>= 8;
    }

    assert(carry === 0);

    length = j;
  }

  // See: https://github.com/bitcoin/bitcoin/commit/2bcf1fc4
  i = size - length;

  const out = Buffer.alloc(zeroes + (size - i));

  let j;

  for (j = 0; j < zeroes; j++)
    out[j] = 0;

  while (i < size)
    out[j++] = b256[i++];

  return out;
}

/**
 * Test whether the string is a base58 string.
 * @param {String} str
 * @returns {Buffer}
 */

function test(str) {
  assert(typeof str === 'string');

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch & 0xff80)
      return false;

    if (TABLE[ch] === -1)
      return false;
  }

  return true;
}

/*
 * Expose
 */

exports.native = 0;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
}],
[/* 14 */ 'bcrypto', '/lib/internal/assert.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * assert.js - assert for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

/*
 * Assert
 */

function assert(val, msg) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
}

/*
 * Expose
 */

module.exports = assert;
}],
[/* 15 */ 'bcrypto', '/lib/sha512-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * sha512.js - sha512 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(16 /* './js/sha512' */);
}],
[/* 16 */ 'bcrypto', '/lib/js/sha512.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * sha512.js - SHA512 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hash.js:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/hash.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/sha/512.js
 */

/* eslint camelcase: "off" */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/*
 * Constants
 */

const FINALIZED = -1;
const DESC = Buffer.alloc(16, 0x00);
const PADDING = Buffer.alloc(128, 0x00);

PADDING[0] = 0x80;

const K = new Uint32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd,
  0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe,
  0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1,
  0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483,
  0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210,
  0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926,
  0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8,
  0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910,
  0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53,
  0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60,
  0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9,
  0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207,
  0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6,
  0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493,
  0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a,
  0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
]);

/**
 * SHA512
 */

class SHA512 {
  constructor() {
    this.state = new Uint32Array(16);
    this.msg = new Uint32Array(160);
    this.block = Buffer.alloc(128);
    this.size = FINALIZED;
  }

  init() {
    this.state[0] = 0x6a09e667;
    this.state[1] = 0xf3bcc908;
    this.state[2] = 0xbb67ae85;
    this.state[3] = 0x84caa73b;
    this.state[4] = 0x3c6ef372;
    this.state[5] = 0xfe94f82b;
    this.state[6] = 0xa54ff53a;
    this.state[7] = 0x5f1d36f1;
    this.state[8] = 0x510e527f;
    this.state[9] = 0xade682d1;
    this.state[10] = 0x9b05688c;
    this.state[11] = 0x2b3e6c1f;
    this.state[12] = 0x1f83d9ab;
    this.state[13] = 0xfb41bd6b;
    this.state[14] = 0x5be0cd19;
    this.state[15] = 0x137e2179;
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(64));
  }

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 127;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 128 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 128)
        return;

      this._transform(this.block, 0);
    }

    while (len >= 128) {
      this._transform(data, off);
      off += 128;
      len -= 128;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  /**
   * Finalize SHA512 context.
   * @private
   * @param {Buffer} out
   * @returns {Buffer}
   */

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const pos = this.size & 127;
    const len = this.size * 8;

    writeU32(DESC, (len * (1 / 0x100000000)) >>> 0, 8);
    writeU32(DESC, len >>> 0, 12);

    this._update(PADDING, 1 + ((239 - pos) & 127));
    this._update(DESC, 16);

    for (let i = 0; i < 16; i++) {
      writeU32(out, this.state[i], i * 4);
      this.state[i] = 0;
    }

    for (let i = 0; i < 160; i++)
      this.msg[i] = 0;

    for (let i = 0; i < 128; i++)
      this.block[i] = 0;

    this.size = FINALIZED;

    return out;
  }

  _prepare(chunk, pos) {
    const W = this.msg;

    let i = 0;

    for (; i < 32; i++)
      W[i] = readU32(chunk, pos + i * 4);

    for (; i < 160; i += 2) {
      const c0_hi = g1_512_hi(W[i - 4], W[i - 3]);
      const c0_lo = g1_512_lo(W[i - 4], W[i - 3]);
      const c1_hi = W[i - 14];
      const c1_lo = W[i - 13];
      const c2_hi = g0_512_hi(W[i - 30], W[i - 29]);
      const c2_lo = g0_512_lo(W[i - 30], W[i - 29]);
      const c3_hi = W[i - 32];
      const c3_lo = W[i - 31];

      W[i + 0] = sum64_4_hi(c0_hi, c0_lo,
                            c1_hi, c1_lo,
                            c2_hi, c2_lo,
                            c3_hi, c3_lo);

      W[i + 1] = sum64_4_lo(c0_hi, c0_lo,
                            c1_hi, c1_lo,
                            c2_hi, c2_lo,
                            c3_hi, c3_lo);
    }
  }

  _transform(chunk, pos) {
    const W = this.msg;

    this._prepare(chunk, pos);

    let ah = this.state[0];
    let al = this.state[1];
    let bh = this.state[2];
    let bl = this.state[3];
    let ch = this.state[4];
    let cl = this.state[5];
    let dh = this.state[6];
    let dl = this.state[7];
    let eh = this.state[8];
    let el = this.state[9];
    let fh = this.state[10];
    let fl = this.state[11];
    let gh = this.state[12];
    let gl = this.state[13];
    let hh = this.state[14];
    let hl = this.state[15];

    for (let i = 0; i < W.length; i += 2) {
      let c0_hi = hh;
      let c0_lo = hl;
      let c1_hi = s1_512_hi(eh, el);
      let c1_lo = s1_512_lo(eh, el);

      const c2_hi = ch64_hi(eh, el, fh, fl, gh, gl);
      const c2_lo = ch64_lo(eh, el, fh, fl, gh, gl);
      const c3_hi = K[i + 0];
      const c3_lo = K[i + 1];
      const c4_hi = W[i + 0];
      const c4_lo = W[i + 1];

      const T1_hi = sum64_5_hi(c0_hi, c0_lo,
                               c1_hi, c1_lo,
                               c2_hi, c2_lo,
                               c3_hi, c3_lo,
                               c4_hi, c4_lo);

      const T1_lo = sum64_5_lo(c0_hi, c0_lo,
                               c1_hi, c1_lo,
                               c2_hi, c2_lo,
                               c3_hi, c3_lo,
                               c4_hi, c4_lo);

      c0_hi = s0_512_hi(ah, al);
      c0_lo = s0_512_lo(ah, al);
      c1_hi = maj64_hi(ah, al, bh, bl, ch, cl);
      c1_lo = maj64_lo(ah, al, bh, bl, ch, cl);

      const T2_hi = sum64_hi(c0_hi, c0_lo, c1_hi, c1_lo);
      const T2_lo = sum64_lo(c0_hi, c0_lo, c1_hi, c1_lo);

      hh = gh;
      hl = gl;

      gh = fh;
      gl = fl;

      fh = eh;
      fl = el;

      eh = sum64_hi(dh, dl, T1_hi, T1_lo);
      el = sum64_lo(dl, dl, T1_hi, T1_lo);

      dh = ch;
      dl = cl;

      ch = bh;
      cl = bl;

      bh = ah;
      bl = al;

      ah = sum64_hi(T1_hi, T1_lo, T2_hi, T2_lo);
      al = sum64_lo(T1_hi, T1_lo, T2_hi, T2_lo);
    }

    sum64(this.state, 0, ah, al);
    sum64(this.state, 2, bh, bl);
    sum64(this.state, 4, ch, cl);
    sum64(this.state, 6, dh, dl);
    sum64(this.state, 8, eh, el);
    sum64(this.state, 10, fh, fl);
    sum64(this.state, 12, gh, gl);
    sum64(this.state, 14, hh, hl);
  }

  static hash() {
    return new SHA512();
  }

  static hmac() {
    return new HMAC(SHA512, 128);
  }

  static digest(data) {
    return SHA512.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 64);
    assert(Buffer.isBuffer(right) && right.length === 64);
    return SHA512.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = SHA512;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return SHA512.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

SHA512.native = 0;
SHA512.id = 'SHA512';
SHA512.size = 64;
SHA512.bits = 512;
SHA512.blockSize = 128;
SHA512.zero = Buffer.alloc(64, 0x00);
SHA512.ctx = new SHA512();

/*
 * Helpers
 */

function sum64(buf, pos, ah, al) {
  const bh = buf[pos + 0];
  const bl = buf[pos + 1];

  const lo = (al + bl) >>> 0;
  const hi = (lo < al) + ah + bh;

  buf[pos + 0] = hi >>> 0;
  buf[pos + 1] = lo;
}

function sum64_hi(ah, al, bh, bl) {
  const lo = (al + bl) >>> 0;
  const hi = (lo < al) + ah + bh;
  return hi >>> 0;
}

function sum64_lo(ah, al, bh, bl) {
  const lo = al + bl;
  return lo >>> 0;
}

function sum64_4_hi(ah, al, bh, bl, ch, cl, dh, dl) {
  let carry = 0;
  let lo = al;

  lo = (lo + bl) >>> 0;
  carry += (lo < al);

  lo = (lo + cl) >>> 0;
  carry += (lo < cl);

  lo = (lo + dl) >>> 0;
  carry += (lo < dl);

  const hi = ah + bh + ch + dh + carry;

  return hi >>> 0;
}

function sum64_4_lo(ah, al, bh, bl, ch, cl, dh, dl) {
  const lo = al + bl + cl + dl;
  return lo >>> 0;
}

function sum64_5_hi(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
  let carry = 0;
  let lo = al;

  lo = (lo + bl) >>> 0;
  carry += (lo < al);

  lo = (lo + cl) >>> 0;
  carry += (lo < cl);

  lo = (lo + dl) >>> 0;
  carry += (lo < dl);

  lo = (lo + el) >>> 0;
  carry += (lo < el);

  const hi = ah + bh + ch + dh + eh + carry;

  return hi >>> 0;
}

function sum64_5_lo(ah, al, bh, bl, ch, cl, dh, dl, eh, el) {
  const lo = al + bl + cl + dl + el;
  return lo >>> 0;
}

function rotr64_hi(ah, al, num) {
  const r = (al << (32 - num)) | (ah >>> num);
  return r >>> 0;
}

function rotr64_lo(ah, al, num) {
  const r = (ah << (32 - num)) | (al >>> num);
  return r >>> 0;
}

function shr64_hi(ah, al, num) {
  return ah >>> num;
}

function shr64_lo(ah, al, num) {
  const r = (ah << (32 - num)) | (al >>> num);
  return r >>> 0;
}

function ch64_hi(xh, xl, yh, yl, zh, zl) {
  const r = (xh & yh) ^ ((~xh) & zh);
  return r >>> 0;
}

function ch64_lo(xh, xl, yh, yl, zh, zl) {
  const r = (xl & yl) ^ ((~xl) & zl);
  return r >>> 0;
}

function maj64_hi(xh, xl, yh, yl, zh, zl) {
  const r = (xh & yh) ^ (xh & zh) ^ (yh & zh);
  return r >>> 0;
}

function maj64_lo(xh, xl, yh, yl, zh, zl) {
  const r = (xl & yl) ^ (xl & zl) ^ (yl & zl);
  return r >>> 0;
}

function s0_512_hi(xh, xl) {
  const c0_hi = rotr64_hi(xh, xl, 28);
  const c1_hi = rotr64_hi(xl, xh, 2); // 34
  const c2_hi = rotr64_hi(xl, xh, 7); // 39
  const r = c0_hi ^ c1_hi ^ c2_hi;
  return r >>> 0;
}

function s0_512_lo(xh, xl) {
  const c0_lo = rotr64_lo(xh, xl, 28);
  const c1_lo = rotr64_lo(xl, xh, 2); // 34
  const c2_lo = rotr64_lo(xl, xh, 7); // 39
  const r = c0_lo ^ c1_lo ^ c2_lo;
  return r >>> 0;
}

function s1_512_hi(xh, xl) {
  const c0_hi = rotr64_hi(xh, xl, 14);
  const c1_hi = rotr64_hi(xh, xl, 18);
  const c2_hi = rotr64_hi(xl, xh, 9); // 41
  const r = c0_hi ^ c1_hi ^ c2_hi;
  return r >>> 0;
}

function s1_512_lo(xh, xl) {
  const c0_lo = rotr64_lo(xh, xl, 14);
  const c1_lo = rotr64_lo(xh, xl, 18);
  const c2_lo = rotr64_lo(xl, xh, 9); // 41
  const r = c0_lo ^ c1_lo ^ c2_lo;
  return r >>> 0;
}

function g0_512_hi(xh, xl) {
  const c0_hi = rotr64_hi(xh, xl, 1);
  const c1_hi = rotr64_hi(xh, xl, 8);
  const c2_hi = shr64_hi(xh, xl, 7);
  const r = c0_hi ^ c1_hi ^ c2_hi;
  return r >>> 0;
}

function g0_512_lo(xh, xl) {
  const c0_lo = rotr64_lo(xh, xl, 1);
  const c1_lo = rotr64_lo(xh, xl, 8);
  const c2_lo = shr64_lo(xh, xl, 7);
  const r = c0_lo ^ c1_lo ^ c2_lo;
  return r >>> 0;
}

function g1_512_hi(xh, xl) {
  const c0_hi = rotr64_hi(xh, xl, 19);
  const c1_hi = rotr64_hi(xl, xh, 29); // 61
  const c2_hi = shr64_hi(xh, xl, 6);
  const r = c0_hi ^ c1_hi ^ c2_hi;
  return r >>> 0;
}

function g1_512_lo(xh, xl) {
  const c0_lo = rotr64_lo(xh, xl, 19);
  const c1_lo = rotr64_lo(xl, xh, 29); // 61
  const c2_lo = shr64_lo(xh, xl, 6);
  const r = c0_lo ^ c1_lo ^ c2_lo;
  return r >>> 0;
}

function readU32(data, off) {
  return (data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function writeU32(data, num, off) {
  data[off++] = num >>> 24;
  data[off++] = num >>> 16;
  data[off++] = num >>> 8;
  data[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = SHA512;
}],
[/* 17 */ 'bcrypto', '/lib/internal/hmac.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hmac.js - hmac for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hash.js:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/hash.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/HMAC
 *   https://tools.ietf.org/html/rfc2104
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/hmac.js
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);

/**
 * HMAC
 */

class HMAC {
  /**
   * Create an HMAC.
   * @param {Function} Hash
   * @param {Number} size
   * @param {Array} [x=[]]
   * @param {Array} [y=[]]
   */

  constructor(Hash, size, x = [], y = []) {
    assert(typeof Hash === 'function');
    assert((size >>> 0) === size);
    assert(Array.isArray(x));
    assert(Array.isArray(y));

    this.hash = Hash;
    this.size = size;
    this.x = x;
    this.y = y;

    this.inner = new Hash();
    this.outer = new Hash();
  }

  /**
   * Initialize HMAC context.
   * @param {Buffer} data
   */

  init(key) {
    assert(Buffer.isBuffer(key));

    // Shorten key
    if (key.length > this.size) {
      const Hash = this.hash;
      const h = new Hash();

      h.init(...this.x);
      h.update(key);

      key = h.final(...this.y);

      assert(key.length <= this.size);
    }

    // Pad key
    const pad = Buffer.alloc(this.size);

    for (let i = 0; i < key.length; i++)
      pad[i] = key[i] ^ 0x36;

    for (let i = key.length; i < pad.length; i++)
      pad[i] = 0x36;

    this.inner.init(...this.x);
    this.inner.update(pad);

    for (let i = 0; i < key.length; i++)
      pad[i] = key[i] ^ 0x5c;

    for (let i = key.length; i < pad.length; i++)
      pad[i] = 0x5c;

    this.outer.init(...this.x);
    this.outer.update(pad);

    return this;
  }

  /**
   * Update HMAC context.
   * @param {Buffer} data
   */

  update(data) {
    this.inner.update(data);
    return this;
  }

  /**
   * Finalize HMAC context.
   * @returns {Buffer}
   */

  final() {
    this.outer.update(this.inner.final(...this.y));
    return this.outer.final(...this.y);
  }
}

/*
 * Expose
 */

module.exports = HMAC;
}],
[/* 18 */ 'bcrypto', '/lib/hash160-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hash160.js - hash160 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(19 /* './js/hash160' */);
}],
[/* 19 */ 'bcrypto', '/lib/js/hash160.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hash160.js - Hash160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const SHA256 = __node_require__(20 /* './sha256' */);
const RIPEMD160 = __node_require__(21 /* './ripemd160' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/*
 * Constants
 */

const rmd = new RIPEMD160();

/**
 * Hash160
 */

class Hash160 {
  constructor() {
    this.ctx = new SHA256();
  }

  init() {
    this.ctx.init();
    return this;
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  final() {
    const out = Buffer.alloc(32);

    this.ctx._final(out);

    rmd.init();
    rmd.update(out);
    rmd._final(out);

    return out.slice(0, 20);
  }

  static hash() {
    return new Hash160();
  }

  static hmac() {
    return new HMAC(Hash160, 64);
  }

  static digest(data) {
    return Hash160.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return Hash160.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = Hash160;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return Hash160.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

Hash160.native = 0;
Hash160.id = 'HASH160';
Hash160.size = 20;
Hash160.bits = 160;
Hash160.blockSize = 64;
Hash160.zero = Buffer.alloc(20, 0x00);
Hash160.ctx = new Hash160();

/*
 * Expose
 */

module.exports = Hash160;
}],
[/* 20 */ 'bcrypto', '/lib/js/sha256.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * sha256.js - SHA256 implementation for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hash.js:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/hash.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/sha/256.js
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/*
 * Constants
 */

const FINALIZED = -1;
const DESC = Buffer.alloc(8, 0x00);
const PADDING = Buffer.alloc(64, 0x00);

PADDING[0] = 0x80;

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

/**
 * SHA256
 */

class SHA256 {
  constructor() {
    this.state = new Uint32Array(8);
    this.msg = new Uint32Array(64);
    this.block = Buffer.alloc(64);
    this.size = FINALIZED;
  }

  init() {
    this.state[0] = 0x6a09e667;
    this.state[1] = 0xbb67ae85;
    this.state[2] = 0x3c6ef372;
    this.state[3] = 0xa54ff53a;
    this.state[4] = 0x510e527f;
    this.state[5] = 0x9b05688c;
    this.state[6] = 0x1f83d9ab;
    this.state[7] = 0x5be0cd19;
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(32));
  }

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 63;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 64 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 64)
        return;

      this._transform(this.block, 0);
    }

    while (len >= 64) {
      this._transform(data, off);
      off += 64;
      len -= 64;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const pos = this.size & 63;
    const len = this.size * 8;

    writeU32(DESC, (len * (1 / 0x100000000)) >>> 0, 0);
    writeU32(DESC, len >>> 0, 4);

    this._update(PADDING, 1 + ((119 - pos) & 63));
    this._update(DESC, 8);

    for (let i = 0; i < 8; i++) {
      writeU32(out, this.state[i], i * 4);
      this.state[i] = 0;
    }

    for (let i = 0; i < 64; i++)
      this.msg[i] = 0;

    for (let i = 0; i < 64; i++)
      this.block[i] = 0;

    this.size = FINALIZED;

    return out;
  }

  _transform(chunk, pos) {
    const W = this.msg;

    let a = this.state[0];
    let b = this.state[1];
    let c = this.state[2];
    let d = this.state[3];
    let e = this.state[4];
    let f = this.state[5];
    let g = this.state[6];
    let h = this.state[7];
    let i = 0;

    for (; i < 16; i++)
      W[i] = readU32(chunk, pos + i * 4);

    for (; i < 64; i++)
      W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

    for (i = 0; i < 64; i++) {
      const t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
      const t2 = Sigma0(a) + Maj(a, b, c);

      h = g;
      g = f;
      f = e;

      e = (d + t1) >>> 0;

      d = c;
      c = b;
      b = a;

      a = (t1 + t2) >>> 0;
    }

    this.state[0] += a;
    this.state[1] += b;
    this.state[2] += c;
    this.state[3] += d;
    this.state[4] += e;
    this.state[5] += f;
    this.state[6] += g;
    this.state[7] += h;
  }

  static hash() {
    return new SHA256();
  }

  static hmac() {
    return new HMAC(SHA256, 64);
  }

  static digest(data) {
    return SHA256.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return SHA256.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = SHA256;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return SHA256.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

SHA256.native = 0;
SHA256.id = 'SHA256';
SHA256.size = 32;
SHA256.bits = 256;
SHA256.blockSize = 64;
SHA256.zero = Buffer.alloc(32, 0x00);
SHA256.ctx = new SHA256();

/*
 * Helpers
 */

function Sigma0(x) {
  return (x >>> 2 | x << 30) ^ (x >>> 13 | x << 19) ^ (x >>> 22 | x << 10);
}

function Sigma1(x) {
  return (x >>> 6 | x << 26) ^ (x >>> 11 | x << 21) ^ (x >>> 25 | x << 7);
}

function sigma0(x) {
  return (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3);
}

function sigma1(x) {
  return (x >>> 17 | x << 15) ^ (x >>> 19 | x << 13) ^ (x >>> 10);
}

function Ch(x, y, z) {
  return z ^ (x & (y ^ z));
}

function Maj(x, y, z) {
  return (x & y) | (z & (x | y));
}

function readU32(data, off) {
  return (data[off++] * 0x1000000
        + data[off++] * 0x10000
        + data[off++] * 0x100
        + data[off]);
}

function writeU32(data, num, off) {
  data[off++] = num >>> 24;
  data[off++] = num >>> 16;
  data[off++] = num >>> 8;
  data[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = SHA256;
}],
[/* 21 */ 'bcrypto', '/lib/js/ripemd160.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * ripemd160.js - RIPEMD160 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hash.js:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/hash.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/RIPEMD-160
 *   https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf
 *   https://github.com/indutny/hash.js/blob/master/lib/hash/ripemd.js
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/*
 * Constants
 */

const FINALIZED = -1;
const DESC = Buffer.alloc(8, 0x00);
const PADDING = Buffer.alloc(64, 0x00);

PADDING[0] = 0x80;

const r = new Uint8Array([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]);

const rh = new Uint8Array([
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]);

const s = new Uint8Array([
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]);

const sh = new Uint8Array([
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]);

/**
 * RIPEMD160
 */

class RIPEMD160 {
  constructor() {
    this.state = new Uint32Array(5);
    this.msg = new Uint32Array(16);
    this.block = Buffer.alloc(64);
    this.size = FINALIZED;
  }

  init() {
    this.state[0] = 0x67452301;
    this.state[1] = 0xefcdab89;
    this.state[2] = 0x98badcfe;
    this.state[3] = 0x10325476;
    this.state[4] = 0xc3d2e1f0;
    this.size = 0;
    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this._update(data, data.length);
    return this;
  }

  final() {
    return this._final(Buffer.alloc(20));
  }

  _update(data, len) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    let pos = this.size & 63;
    let off = 0;

    this.size += len;

    if (pos > 0) {
      let want = 64 - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < 64)
        return;

      this._transform(this.block, 0);
    }

    while (len >= 64) {
      this._transform(data, off);
      off += 64;
      len -= 64;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);
  }

  _final(out) {
    assert(this.size !== FINALIZED, 'Context is not initialized.');

    const pos = this.size & 63;
    const len = this.size * 8;

    writeU32(DESC, len >>> 0, 0);
    writeU32(DESC, (len * (1 / 0x100000000)) >>> 0, 4);

    this._update(PADDING, 1 + ((119 - pos) & 63));
    this._update(DESC, 8);

    for (let i = 0; i < 5; i++) {
      writeU32(out, this.state[i], i * 4);
      this.state[i] = 0;
    }

    for (let i = 0; i < 16; i++)
      this.msg[i] = 0;

    for (let i = 0; i < 64; i++)
      this.block[i] = 0;

    this.size = FINALIZED;

    return out;
  }

  _transform(chunk, pos) {
    const W = this.msg;

    let A = this.state[0];
    let B = this.state[1];
    let C = this.state[2];
    let D = this.state[3];
    let E = this.state[4];
    let Ah = A;
    let Bh = B;
    let Ch = C;
    let Dh = D;
    let Eh = E;

    for (let i = 0; i < 16; i++)
      W[i] = readU32(chunk, pos + i * 4);

    for (let j = 0; j < 80; j++) {
      let a = A + f(j, B, C, D) + W[r[j]] + K(j);
      let b = rotl32(a, s[j]);
      let T = b + E;

      A = E;
      E = D;
      D = rotl32(C, 10);
      C = B;
      B = T;

      a = Ah + f(79 - j, Bh, Ch, Dh) + W[rh[j]] + Kh(j);
      b = rotl32(a, sh[j]);
      T = b + Eh;
      Ah = Eh;
      Eh = Dh;
      Dh = rotl32(Ch, 10);
      Ch = Bh;
      Bh = T;
    }

    const T = this.state[1] + C + Dh;

    this.state[1] = this.state[2] + D + Eh;
    this.state[2] = this.state[3] + E + Ah;
    this.state[3] = this.state[4] + A + Bh;
    this.state[4] = this.state[0] + B + Ch;
    this.state[0] = T;
  }

  static hash() {
    return new RIPEMD160();
  }

  static hmac() {
    return new HMAC(RIPEMD160, 64);
  }

  static digest(data) {
    return RIPEMD160.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 20);
    assert(Buffer.isBuffer(right) && right.length === 20);
    return RIPEMD160.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = RIPEMD160;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return RIPEMD160.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

RIPEMD160.native = 0;
RIPEMD160.id = 'RIPEMD160';
RIPEMD160.size = 20;
RIPEMD160.bits = 160;
RIPEMD160.blockSize = 64;
RIPEMD160.zero = Buffer.alloc(20, 0x00);
RIPEMD160.ctx = new RIPEMD160();

/*
 * Helpers
 */

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function f(j, x, y, z) {
  if (j <= 15)
    return x ^ y ^ z;

  if (j <= 31)
    return (x & y) | ((~x) & z);

  if (j <= 47)
    return (x | (~y)) ^ z;

  if (j <= 63)
    return (x & z) | (y & (~z));

  return x ^ (y | (~z));
}

function K(j) {
  if (j <= 15)
    return 0x00000000;

  if (j <= 31)
    return 0x5a827999;

  if (j <= 47)
    return 0x6ed9eba1;

  if (j <= 63)
    return 0x8f1bbcdc;

  return 0xa953fd4e;
}

function Kh(j) {
  if (j <= 15)
    return 0x50a28be6;

  if (j <= 31)
    return 0x5c4dd124;

  if (j <= 47)
    return 0x6d703ef3;

  if (j <= 63)
    return 0x7a6d76e9;

  return 0x00000000;
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = RIPEMD160;
}],
[/* 22 */ 'bcrypto', '/lib/hash256-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hash256.js - hash256 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(23 /* './js/hash256' */);
}],
[/* 23 */ 'bcrypto', '/lib/js/hash256.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hash256.js - Hash256 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://github.com/bitcoin/bitcoin/blob/master/src/hash.h
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const SHA256 = __node_require__(20 /* './sha256' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/**
 * Hash256
 */

class Hash256 {
  constructor() {
    this.ctx = new SHA256();
  }

  init() {
    this.ctx.init();
    return this;
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  final() {
    const out = Buffer.alloc(32);

    this.ctx._final(out);
    this.ctx.init();
    this.ctx.update(out);
    this.ctx._final(out);

    return out;
  }

  static hash() {
    return new Hash256();
  }

  static hmac() {
    return new HMAC(Hash256, 64);
  }

  static digest(data) {
    return Hash256.ctx.init().update(data).final();
  }

  static root(left, right) {
    assert(Buffer.isBuffer(left) && left.length === 32);
    assert(Buffer.isBuffer(right) && right.length === 32);
    return Hash256.ctx.init().update(left).update(right).final();
  }

  static multi(x, y, z) {
    const {ctx} = Hash256;

    ctx.init();
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key) {
    return Hash256.hmac().init(key).update(data).final();
  }
}

/*
 * Static
 */

Hash256.native = 0;
Hash256.id = 'HASH256';
Hash256.size = 32;
Hash256.bits = 256;
Hash256.blockSize = 64;
Hash256.zero = Buffer.alloc(32, 0x00);
Hash256.ctx = new Hash256();

/*
 * Expose
 */

module.exports = Hash256;
}],
[/* 24 */ 'bcrypto', '/lib/cleanse-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * cleanse.js - cleanse for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(25 /* './js/cleanse' */);
}],
[/* 25 */ 'bcrypto', '/lib/js/cleanse.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * cleanse.js - memzero for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const random = __node_require__(26 /* '../random' */);

/**
 * A maybe-secure memzero.
 * @param {Buffer} data
 */

function cleanse(data) {
  assert(Buffer.isBuffer(data));
  random.randomFill(data, 0, data.length);
}

/*
 * Static
 */

cleanse.native = 0;

/*
 * Expose
 */

module.exports = cleanse;
}],
[/* 26 */ 'bcrypto', '/lib/random-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * random.js - random for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(27 /* './js/random' */);
}],
[/* 27 */ 'bcrypto', '/lib/js/random.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * random.js - random number generator for bcrypto
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://wiki.openssl.org/index.php/Random_Numbers
 *   https://csrc.nist.gov/projects/random-bit-generation/
 *   http://www.pcg-random.org/posts/bounded-rands.html
 *   https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);

/*
 * Constants
 */

const crypto = global.crypto || global.msCrypto;
const HAS_CRYPTO = crypto && typeof crypto.getRandomValues === 'function';
const randomValues = HAS_CRYPTO ? crypto.getRandomValues.bind(crypto) : null;
const pool = new Uint32Array(16);
const MAX_BYTES = 65536;

let poolPos = 0;

/**
 * Generate pseudo-random bytes.
 * @param {Number} size
 * @returns {Buffer}
 */

function randomBytes(size) {
  assert((size >>> 0) === size);

  const data = Buffer.alloc(size);

  randomFillSync(data, 0, size);

  return data;
}

/**
 * Generate pseudo-random bytes.
 * @param {Buffer} data
 * @param {Number} [off=0]
 * @param {Number} [size=data.length-off]
 * @returns {Buffer}
 */

function randomFill(data, off, size) {
  assert(Buffer.isBuffer(data));

  if (off == null)
    off = 0;

  assert((off >>> 0) === off);

  if (size == null)
    size = data.length - off;

  assert((size >>> 0) === size);
  assert(off + size <= data.length);

  randomFillSync(data, off, size);

  return data;
}

/**
 * Generate a random uint32.
 * @returns {Number}
 */

function randomInt() {
  if ((poolPos & 15) === 0) {
    getRandomValues(pool);
    poolPos = 0;
  }

  return pool[poolPos++];
}

/**
 * Generate a random uint32 within a range.
 * @param {Number} min - Inclusive.
 * @param {Number} max - Exclusive.
 * @returns {Number}
 */

function randomRange(min, max) {
  assert((min >>> 0) === min);
  assert((max >>> 0) === max);
  assert(max >= min);

  const space = max - min;

  if (space === 0)
    return min;

  const top = -space >>> 0;

  let x, r;

  do {
    x = randomInt();
    r = x % space;
  } while (x - r > top);

  return r + min;
}

/*
 * Helpers
 */

function getRandomValues(array) {
  if (!HAS_CRYPTO)
    throw new Error('Entropy source not available.');

  return randomValues(array);
}

function randomFillSync(data, off, size) {
  assert(Buffer.isBuffer(data));
  assert(data.buffer instanceof ArrayBuffer);
  assert((data.byteOffset >>> 0) === data.byteOffset);
  assert((data.byteLength >>> 0) === data.byteLength);
  assert((off >>> 0) === off);
  assert((size >>> 0) === size);
  assert(off + size <= data.byteLength);

  if (size > 2 ** 31 - 1)
    throw new RangeError('The value "size" is out of range.');

  const offset = data.byteOffset + off;
  const array = new Uint8Array(data.buffer, offset, size);

  if (array.length > MAX_BYTES) {
    for (let i = 0; i < array.length; i += MAX_BYTES) {
      let j = i + MAX_BYTES;

      if (j > array.length)
        j = array.length;

      getRandomValues(array.subarray(i, j));
    }
  } else {
    if (array.length > 0)
      getRandomValues(array);
  }
}

/*
 * Expose
 */

exports.native = 0;
exports.randomBytes = randomBytes;
exports.randomFill = randomFill;
exports.randomInt = randomInt;
exports.randomRange = randomRange;
}],
[/* 28 */ 'bcrypto', '/lib/secp256k1-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(29 /* './js/secp256k1' */);
}],
[/* 29 */ 'bcrypto', '/lib/js/secp256k1.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * secp256k1.js - secp256k1 for bcrypto
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const ECDSA = __node_require__(30 /* './ecdsa' */);
const SHA256 = __node_require__(39 /* '../sha256' */);
const pre = __node_require__(43 /* './precomputed/secp256k1.json' */);

/*
 * Expose
 */

module.exports = new ECDSA('SECP256K1', SHA256, SHA256, pre);
}],
[/* 30 */ 'bcrypto', '/lib/js/ecdsa.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * ecdsa.js - ECDSA for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * References:
 *
 *   [SEC1] SEC 1: Elliptic Curve Cryptography, Version 2.0
 *     Certicom Research
 *     http://www.secg.org/sec1-v2.pdf
 *
 *   [FIPS186] Suite B Implementer's Guide to FIPS 186-3 (ECDSA)
 *     https://tinyurl.com/fips186-guide
 *
 *   [GECC] Guide to Elliptic Curve Cryptography
 *     D. Hankerson, A. Menezes, and S. Vanstone
 *     https://tinyurl.com/guide-to-ecc
 *
 *   [RFC6979] Deterministic Usage of the Digital Signature
 *             Algorithm (DSA) and Elliptic Curve Digital
 *             Signature Algorithm (ECDSA)
 *     T. Pornin
 *     https://tools.ietf.org/html/rfc6979
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const BN = __node_require__(31 /* '../bn' */);
const rng = __node_require__(26 /* '../random' */);
const asn1 = __node_require__(34 /* '../internal/asn1' */);
const Schnorr = __node_require__(35 /* './schnorr-legacy' */);
const HmacDRBG = __node_require__(40 /* '../hmac-drbg' */);
const elliptic = __node_require__(42 /* './elliptic' */);

/**
 * ECDSA
 */

class ECDSA {
  constructor(name, hash, xof, pre) {
    assert(typeof name === 'string');
    assert(hash);
    assert(xof);

    this.id = name;
    this.type = 'ecdsa';
    this.hash = hash;
    this.xof = xof;
    this.native = 0;

    this._pre = pre || null;
    this._curve = null;
    this._schnorr = null;
  }

  get curve() {
    if (!this._curve) {
      this._curve = elliptic.curve(this.id, this._pre);
      this._curve.precompute(rng);
      this._pre = null;
    }
    return this._curve;
  }

  get schnorr() {
    if (!this._schnorr)
      this._schnorr = new Schnorr(this.curve, this.xof);
    return this._schnorr;
  }

  get size() {
    return this.curve.fieldSize;
  }

  get bits() {
    return this.curve.fieldBits;
  }

  privateKeyGenerate() {
    const a = this.curve.randomScalar(rng);
    return this.curve.encodeScalar(a);
  }

  privateKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    let a;
    try {
      a = this.curve.decodeScalar(key);
    } catch (e) {
      return false;
    }

    return !a.isZero() && a.cmp(this.curve.n) < 0;
  }

  privateKeyExport(key) {
    const pub = this.publicKeyCreate(key, false);
    const {x, y} = this.publicKeyExport(pub);

    return {
      d: Buffer.from(key),
      x,
      y
    };
  }

  privateKeyImport(json) {
    assert(json && typeof json === 'object');

    const a = BN.decode(json.d, this.curve.endian);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(a);
  }

  privateKeyTweakAdd(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.add(t).imod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(k);
  }

  privateKeyTweakMul(key, tweak) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.mul(t).imod(this.curve.n);

    if (k.isZero())
      throw new Error('Invalid private key.');

    return this.curve.encodeScalar(k);
  }

  privateKeyNegate(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.neg().imod(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  privateKeyInvert(key) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const k = a.invert(this.curve.n);

    return this.curve.encodeScalar(k);
  }

  publicKeyCreate(key, compress) {
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    const A = this.curve.g.mulBlind(a);

    return A.encode(compress);
  }

  publicKeyConvert(key, compress) {
    const A = this.curve.decodePoint(key);
    return A.encode(compress);
  }

  publicKeyFromUniform(bytes, compress) {
    const u = this.curve.decodeUniform(bytes);
    const A = this.curve.pointFromUniform(u);

    return A.encode(compress);
  }

  publicKeyToUniform(key, hint = rng.randomInt()) {
    const A = this.curve.decodePoint(key);
    const u = this.curve.pointToUniform(A, hint);

    return this.curve.encodeUniform(u, hint >>> 8);
  }

  publicKeyFromHash(bytes, compress) {
    const A = this.curve.pointFromHash(bytes);
    return A.encode(compress);
  }

  publicKeyToHash(key) {
    const A = this.curve.decodePoint(key);
    return this.curve.pointToHash(A, 0, rng);
  }

  publicKeyVerify(key) {
    assert(Buffer.isBuffer(key));

    try {
      this.curve.decodePoint(key);
    } catch (e) {
      return false;
    }

    return true;
  }

  publicKeyExport(key) {
    const {x, y} = this.curve.decodePoint(key);

    return {
      x: this.curve.encodeField(x.fromRed()),
      y: this.curve.encodeField(y.fromRed())
    };
  }

  publicKeyImport(json, compress) {
    assert(json && typeof json === 'object');

    const x = BN.decode(json.x, this.curve.endian);

    if (x.cmp(this.curve.p) >= 0)
      throw new Error('Invalid point.');

    if (json.y != null) {
      const y = BN.decode(json.y, this.curve.endian);

      if (y.cmp(this.curve.p) >= 0)
        throw new Error('Invalid point.');

      const A = this.curve.point(x, y);

      if (!A.validate())
        throw new Error('Invalid point.');

      return A.encode(compress);
    }

    const A = this.curve.pointFromX(x, json.sign);

    return A.encode(compress);
  }

  publicKeyTweakAdd(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const T = this.curve.g.jmul(t);
    const P = T.add(A);

    return P.encode(compress);
  }

  publicKeyTweakMul(key, tweak, compress) {
    const t = this.curve.decodeScalar(tweak);

    if (t.isZero() || t.cmp(this.curve.n) >= 0)
      throw new Error('Invalid scalar.');

    const A = this.curve.decodePoint(key);
    const P = A.mul(t);

    return P.encode(compress);
  }

  publicKeyCombine(keys, compress) {
    assert(Array.isArray(keys));

    let P = this.curve.jpoint();

    for (const key of keys) {
      const A = this.curve.decodePoint(key);

      P = P.add(A);
    }

    return P.encode(compress);
  }

  publicKeyNegate(key, compress) {
    const A = this.curve.decodePoint(key);
    const P = A.neg();

    return P.encode(compress);
  }

  signatureNormalize(sig) {
    const [r, s] = this._decodeCompact(sig);

    if (s.cmp(this.curve.nh) > 0)
      s.ineg().imod(this.curve.n);

    return this._encodeCompact(r, s);
  }

  signatureNormalizeDER(sig) {
    const [r, s] = this._decodeDER(sig, false);

    if (s.cmp(this.curve.nh) > 0)
      s.ineg().imod(this.curve.n);

    return this._encodeDER(r, s);
  }

  signatureExport(sig) {
    const [r, s] = this._decodeCompact(sig);
    return this._encodeDER(r, s);
  }

  signatureImport(sig) {
    const [r, s] = this._decodeDER(sig, false);
    return this._encodeCompact(r, s);
  }

  isLowS(sig) {
    assert(Buffer.isBuffer(sig));

    let s;
    try {
      [, s] = this._decodeCompact(sig);
    } catch (e) {
      return false;
    }

    return s.cmp(this.curve.nh) <= 0;
  }

  isLowDER(sig) {
    assert(Buffer.isBuffer(sig));

    let s;
    try {
      [, s] = this._decodeDER(sig, false);
    } catch (e) {
      return false;
    }

    return s.cmp(this.curve.nh) <= 0;
  }

  sign(msg, key) {
    const [r, s] = this._sign(msg, key);
    return this._encodeCompact(r, s);
  }

  signRecoverable(msg, key) {
    const [r, s, param] = this._sign(msg, key);
    return [this._encodeCompact(r, s), param];
  }

  signDER(msg, key) {
    const [r, s] = this._sign(msg, key);
    return this._encodeDER(r, s);
  }

  signRecoverableDER(msg, key) {
    const [r, s, param] = this._sign(msg, key);
    return [this._encodeDER(r, s), param];
  }

  _sign(msg, key) {
    // ECDSA Signing.
    //
    // [SEC1] Page 44, Section 4.1.3.
    // [GECC] Algorithm 4.29, Page 184, Section 4.4.1.
    // [RFC6979] Page 9, Section 2.4.
    // [RFC6979] Page 10, Section 3.2.
    //
    // Assumptions:
    //
    //   - Let `m` be an integer reduced from bytes.
    //   - Let `a` be a secret non-zero scalar.
    //   - Let `k` be a random non-zero scalar.
    //   - R != O, r != 0, s != 0.
    //
    // Computation:
    //
    //   k = random integer in [1,n-1]
    //   R = G * k
    //   r = x(R) mod n
    //   s = (r * a + m) / k mod n
    //   s = -s mod n, if s > n / 2
    //   S = (r, s)
    //
    // We can blind the scalar arithmetic
    // with a random integer `b` like so:
    //
    //   b = random integer in [1,n-1]
    //   s = (r * (a * b) + m * b) / (k * b) mod n
    //
    // Note that `k` must remain secret,
    // otherwise an attacker can compute:
    //
    //   a = (s * k - m) / r mod n
    //
    // This means that if two signatures
    // share the same `r` value, an attacker
    // can compute:
    //
    //   k = (m1 - m2) / (+-s1 - +-s2) mod n
    //   a = (s1 * k - m1) / r mod n
    //
    // Assuming:
    //
    //   s1 = (r * a + m1) / k mod n
    //   s2 = (r * a + m2) / k mod n
    //
    // To mitigate this, `k` can be generated
    // deterministically using the HMAC-DRBG
    // construction described in [RFC6979].
    const {n, nh} = this.curve;
    const G = this.curve.g;
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(n) >= 0)
      throw new Error('Invalid private key.');

    const m = this._reduce(msg);
    const nonce = this.curve.encodeScalar(m);
    const drbg = new HmacDRBG(this.hash, key, nonce);

    for (;;) {
      const bytes = drbg.generate(this.curve.scalarSize);
      const k = this._truncate(bytes);

      if (k.isZero() || k.cmp(n) >= 0)
        continue;

      const R = G.mulBlind(k);

      if (R.isInfinity())
        continue;

      const x = R.getX();
      const r = x.mod(n);

      if (r.isZero())
        continue;

      const b = this.curve.randomScalar(rng);
      const ki = k.mul(b).fermat(n);
      const ba = a.mul(b).imod(n);
      const bm = m.mul(b).imod(n);
      const sk = r.mul(ba).iadd(bm).imod(n);
      const s = sk.mul(ki).imod(n);

      if (s.isZero())
        continue;

      let param = R.isOdd() | (!x.eq(r) << 1);

      if (s.cmp(nh) > 0) {
        s.ineg().imod(n);
        param ^= 1;
      }

      return [r, s, param];
    }
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    let r, s;
    try {
      [r, s] = this._decodeCompact(sig);
    } catch (e) {
      return false;
    }

    try {
      return this._verify(msg, r, s, key);
    } catch (e) {
      return false;
    }
  }

  verifyDER(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    let r, s;
    try {
      [r, s] = this._decodeDER(sig, false);
    } catch (e) {
      return false;
    }

    try {
      return this._verify(msg, r, s, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, r, s, key) {
    // ECDSA Verification.
    //
    // [SEC1] Page 46, Section 4.1.4.
    // [GECC] Algorithm 4.30, Page 184, Section 4.4.1.
    //
    // Assumptions:
    //
    //   - Let `m` be an integer reduced from bytes.
    //   - Let `r` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - r != 0, r < n.
    //   - s != 0, s < n.
    //   - R != O.
    //
    // Computation:
    //
    //   u1 = m / s mod n
    //   u2 = r / s mod n
    //   R = G * u1 + A * u2
    //   r == x(R) mod n
    //
    // Note that the signer can verify their
    // own signatures more efficiently with:
    //
    //   R = G * ((u1 + u2 * a) mod n)
    //
    // Furthermore, we can avoid affinization
    // of `R` by scaling `r` by `z^2` and
    // repeatedly adding `n * z^2` to it up
    // to a certain threshold.
    const {n} = this.curve;
    const G = this.curve.g;
    const m = this._reduce(msg);
    const A = this.curve.decodePoint(key);

    if (r.isZero() || r.cmp(n) >= 0)
      return false;

    if (s.isZero() || s.cmp(n) >= 0)
      return false;

    const si = s.invert(n);
    const u1 = m.mul(si).imod(n);
    const u2 = r.mul(si).imod(n);
    const R = G.jmulAdd(u1, A, u2);

    return R.eqR(r);
  }

  recover(msg, sig, param, compress) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    let r, s;
    try {
      [r, s] = this._decodeCompact(sig);
    } catch (e) {
      return null;
    }

    let A;
    try {
      A = this._recover(msg, r, s, param);
    } catch (e) {
      return null;
    }

    return A.encode(compress);
  }

  recoverDER(msg, sig, param, compress) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert((param >>> 0) === param);
    assert((param & 3) === param, 'The recovery param is more than two bits.');

    let r, s;
    try {
      [r, s] = this._decodeDER(sig, false);
    } catch (e) {
      return null;
    }

    let A;
    try {
      A = this._recover(msg, r, s, param);
    } catch (e) {
      return null;
    }

    return A.encode(compress);
  }

  _recover(msg, r, s, param) {
    // ECDSA Public Key Recovery.
    //
    // [SEC1] Page 47, Section 4.1.6.
    //
    // Assumptions:
    //
    //   - Let `m` be an integer reduced from bytes.
    //   - Let `r` and `s` be signature elements.
    //   - Let `i` be an integer in [0,3].
    //   - x^3 + a * x + b is square in F(p).
    //   - If i > 1 then r < (p mod n).
    //   - r != 0, r < n.
    //   - s != 0, s < n.
    //   - A != O.
    //
    // Computation:
    //
    //   x = r + n, if i > 1
    //     = r, otherwise
    //   R' = (x, sqrt(x^3 + a * x + b))
    //   R = -R', if i mod 2 == 1
    //     = +R', otherwise
    //   s1 = m / r mod n
    //   s2 = s / r mod n
    //   A = R * s2 - G * s1
    //
    // Note that this implementation will have
    // trouble on curves where `p / n > 1`.
    const {n, pmodn} = this.curve;
    const G = this.curve.g;
    const m = this._reduce(msg);

    if (r.isZero() || r.cmp(n) >= 0)
      throw new Error('Invalid R value.');

    if (s.isZero() || s.cmp(n) >= 0)
      throw new Error('Invalid S value.');

    const sign = (param & 1) !== 0;
    const high = param >>> 1;

    let x = r;

    if (high) {
      if (this.curve.highOrder)
        throw new Error('Invalid high bit.');

      if (x.cmp(pmodn) >= 0)
        throw new Error('Invalid R value.');

      x = x.add(n);
    }

    const R = this.curve.pointFromX(x, sign);
    const ri = r.invert(n);
    const s1 = m.mul(ri).ineg().imod(n);
    const s2 = s.mul(ri).imod(n);
    const A = G.mulAdd(s1, R, s2);

    if (A.isInfinity())
      throw new Error('Invalid point.');

    return A;
  }

  derive(pub, priv, compress) {
    const A = this.curve.decodePoint(pub);
    const a = this.curve.decodeScalar(priv);

    if (a.isZero() || a.cmp(this.curve.n) >= 0)
      throw new Error('Invalid private key.');

    if (this.curve.h.cmpn(1) > 0) {
      if (A.isSmall())
        throw new Error('Invalid point.');
    }

    const P = A.mulBlind(a, rng);

    return P.encode(compress);
  }

  /*
   * Schnorr
   */

  schnorrSign(msg, key) {
    return this.schnorr.sign(msg, key);
  }

  schnorrVerify(msg, sig, key) {
    return this.schnorr.verify(msg, sig, key);
  }

  schnorrVerifyBatch(batch) {
    return this.schnorr.verifyBatch(batch);
  }

  /*
   * Helpers
   */

  _encodeCompact(r, s) {
    return Buffer.concat([
      this.curve.encodeScalar(r),
      this.curve.encodeScalar(s)
    ]);
  }

  _decodeCompact(sig) {
    assert(Buffer.isBuffer(sig));

    const {n} = this.curve;
    const size = this.curve.scalarSize;

    if (sig.length !== size * 2)
      throw new Error('Invalid signature size.');

    const Rraw = sig.slice(0, size);
    const Sraw = sig.slice(size, size * 2);
    const r = this.curve.decodeScalar(Rraw);
    const s = this.curve.decodeScalar(Sraw);

    if (r.cmp(n) >= 0 || s.cmp(n) >= 0)
      throw new Error('Invalid signature.');

    return [r, s];
  }

  _encodeDER(r, s) {
    const size = asn1.sizeInt(r) + asn1.sizeInt(s);
    const out = Buffer.alloc(asn1.sizeSeq(size));

    let pos = 0;

    pos = asn1.writeSeq(out, pos, size);
    pos = asn1.writeInt(out, pos, r);
    pos = asn1.writeInt(out, pos, s);

    assert(pos === out.length);

    return out;
  }

  _decodeDER(sig, strict) {
    assert(Buffer.isBuffer(sig));
    assert(typeof strict === 'boolean');

    const {n} = this.curve;

    let pos = 0;
    let r, s;

    pos = asn1.readSeq(sig, pos, strict);
    [r, pos] = asn1.readInt(sig, pos, strict);
    [s, pos] = asn1.readInt(sig, pos, strict);

    if (strict && pos !== sig.length)
      throw new Error('Trailing bytes.');

    if (r.cmp(n) >= 0 || s.cmp(n) >= 0)
      throw new Error('Invalid signature.');

    return [r, s];
  }

  _truncate(msg) {
    // Byte array to integer conversion.
    //
    // [SEC1] Step 5, Page 45, Section 4.1.3.
    // [FIPS186] Page 25, Section B.2.
    //
    // The two sources above disagree on this.
    //
    // FIPS186 simply modulos the entire byte
    // array by the order, whereas SEC1 takes
    // the left-most ceil(log2(n+1)) bits modulo
    // the order (and maybe does other stuff).
    //
    // Instead of trying to decipher all of
    // this nonsense, we simply replicate the
    // OpenSSL behavior (which, in actuality,
    // is more similar to the SEC1 behavior).
    assert(Buffer.isBuffer(msg));

    const bits = this.curve.n.bitLength();
    const bytes = (bits + 7) >>> 3;

    if (msg.length > bytes)
      msg = msg.slice(0, bytes);

    const m = BN.decode(msg, this.curve.endian);
    const d = msg.length * 8 - bits;

    if (d > 0)
      m.iushrn(d);

    return m;
  }

  _reduce(msg) {
    return this._truncate(msg).imod(this.curve.n);
  }
}

/*
 * Expose
 */

module.exports = ECDSA;
}],
[/* 31 */ 'bcrypto', '/lib/bn-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(32 /* './js/bn' */);
}],
[/* 32 */ 'bcrypto', '/lib/js/bn.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * bn.js - big numbers for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/bn.js:
 *   Copyright (c) 2015, Fedor Indutny (MIT License).
 *   https://github.com/indutny/bn.js
 *
 * Parts of this software are based on golang/go:
 *   Copyright (c) 2009, The Go Authors. All rights reserved.
 *   https://github.com/golang/go
 *
 * Parts of this software are based on openssl/openssl:
 *   Copyright (c) 1998-2018, The OpenSSL Project (Apache License v2.0).
 *   Copyright (c) 1995-1998, Eric A. Young, Tim J. Hudson. All rights reserved.
 *   https://github.com/openssl/openssl
 *
 * Parts of this software are based on libgmp:
 *   Copyright (c) 1991-1997, 1999-2014, Free Software Foundation, Inc.
 *   https://gmplib.org/
 *
 * Parts of this software are based on v8/v8:
 *   Copyright (c) 2017, The V8 Project Authors (BSD-Style License).
 *   https://github.com/v8/v8
 *
 * Resources:
 *   https://github.com/indutny/bn.js/blob/master/lib/bn.js
 *   https://github.com/indutny/miller-rabin/blob/master/lib/mr.js
 *   https://github.com/golang/go/blob/master/src/math/big/int.go
 *   https://github.com/golang/go/blob/master/src/math/big/nat.go
 *   https://github.com/golang/go/blob/master/src/math/big/prime.go
 *   https://github.com/openssl/openssl/tree/master/crypto/bn
 *   https://github.com/openssl/openssl/blob/master/crypto/bn/bn_kron.c
 *   https://github.com/gnutls/nettle/blob/master/mini-gmp.c
 *   https://github.com/v8/v8/blob/master/src/objects/bigint.cc
 */

/* eslint valid-typeof: "off" */

'use strict';

const {custom} = __node_require__(33 /* '../internal/custom' */);

/*
 * Constants
 */

const zeros = [
  '',
  '0',
  '00',
  '000',
  '0000',
  '00000',
  '000000',
  '0000000',
  '00000000',
  '000000000',
  '0000000000',
  '00000000000',
  '000000000000',
  '0000000000000',
  '00000000000000',
  '000000000000000',
  '0000000000000000',
  '00000000000000000',
  '000000000000000000',
  '0000000000000000000',
  '00000000000000000000',
  '000000000000000000000',
  '0000000000000000000000',
  '00000000000000000000000',
  '000000000000000000000000',
  '0000000000000000000000000'
];

const groupSizes = [
  0x00, 0x19, 0x10, 0x0c, 0x0b, 0x0a,
  0x09, 0x08, 0x08, 0x07, 0x07, 0x07,
  0x07, 0x06, 0x06, 0x06, 0x06, 0x06,
  0x06, 0x06, 0x05, 0x05, 0x05, 0x05,
  0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
  0x05, 0x05, 0x05, 0x05, 0x05, 0x05
];

const groupBases = [
  0x00000000, 0x02000000, 0x0290d741, 0x01000000,
  0x02e90edd, 0x039aa400, 0x0267bf47, 0x01000000,
  0x0290d741, 0x00989680, 0x012959c3, 0x0222c000,
  0x03bd7765, 0x0072e440, 0x00adcea1, 0x01000000,
  0x01704f61, 0x0206fc40, 0x02cddcf9, 0x03d09000,
  0x003e5185, 0x004ea360, 0x006235f7, 0x00798000,
  0x009502f9, 0x00b54ba0, 0x00daf26b, 0x01069c00,
  0x0138f9ad, 0x0172c9e0, 0x01b4d89f, 0x02000000,
  0x025528a1, 0x02b54a20, 0x03216b93, 0x039aa400
];

const primes = {
  p192: null,
  p224: null,
  p521: null,
  k256: null,
  p251: null,
  p25519: null,
  p448: null
};

const modes = {
  NONE: 0,
  QUO: 1,
  REM: 2,
  BOTH: 3,
  EUCLID: 4,
  ALL: 7
};

const WND_WIDTH = 4;
const WND_SIZE = 1 << (WND_WIDTH - 1);

const HAS_BIGINT = typeof BigInt === 'function';

/**
 * BN
 */

class BN {
  constructor(num, base, endian) {
    this.words = [0];
    this.length = 1;
    this.negative = 0;
    this.red = null;
    this.from(num, base, endian);
  }

  /*
   * Addition Engine
   */

  _iadd(a, b) {
    let carry = 0;
    let i = 0;

    // a.length > b.length
    if (a.length < b.length)
      [a, b] = [b, a];

    if (a !== this)
      this._alloc(a.length);

    for (; i < b.length; i++) {
      const r = (a.words[i] | 0) + (b.words[i] | 0) + carry;

      this.words[i] = r & 0x3ffffff;

      carry = r >>> 26;
    }

    for (; carry !== 0 && i < a.length; i++) {
      const r = (a.words[i] | 0) + carry;

      this.words[i] = r & 0x3ffffff;

      carry = r >>> 26;
    }

    this.length = a.length;

    if (carry !== 0) {
      this._alloc(this.length + 1);
      this.words[this.length++] = carry;
    } else if (a !== this) {
      // Copy the rest of the words.
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    // Note: we shouldn't need to strip here.
    return this;
  }

  _iaddn(num) {
    this.words[0] += num;

    if (this.words[0] < 0x4000000)
      return this;

    // Carry.
    let i = 0;

    this._alloc(this.length + 1);

    this.words[this.length] = 0;

    for (; i < this.length && this.words[i] >= 0x4000000; i++) {
      this.words[i] -= 0x4000000;
      this.words[i + 1] += 1;
    }

    this.length = Math.max(this.length, i + 1);

    // Note: we shouldn't need to strip here.
    return this;
  }

  /*
   * Addition
   */

  iadd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.negative === num.negative) {
      // x + y == x + y
      // (-x) + (-y) == -(x + y)
      this._iadd(this, num);
    } else {
      // x + (-y) == x - y == -(y - x)
      // (-x) + y == y - x == -(x - y)
      const cmp = this.ucmp(num);

      // x + (-x) == (-x) + x == 0
      if (cmp === 0) {
        this.words[0] = 0;
        this.length = 1;
        this.negative = 0;
        return this;
      }

      if (cmp < 0) {
        this._isub(num, this);
        this.negative ^= 1;
      } else {
        this._isub(this, num);
      }
    }

    return this;
  }

  iaddn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const negative = (num < 0) | 0;

    if (negative)
      num = -num;

    if (this.negative === negative) {
      // x + y == x + y
      // (-x) + (-y) == -(x + y)
      this._iaddn(num);
    } else {
      // x + (-y) == x - y == -(y - x)
      // (-x) + y == y - x == -(x - y)
      if (this.length === 1 && this.words[0] < num) {
        this.words[0] = num - this.words[0];
        this.negative ^= 1;
      } else {
        this._isubn(num);
      }
    }

    return this;
  }

  add(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (num.length > this.length)
      return num.clone().iadd(this);

    return this.clone().iadd(num);
  }

  addn(num) {
    return this.clone().iaddn(num);
  }

  /*
   * Subtraction Engine
   */

  _isub(a, b) {
    let carry = 0;
    let i = 0;

    // a > b
    assert(a.length >= b.length);

    if (a !== this)
      this._alloc(a.length);

    for (; i < b.length; i++) {
      const r = (a.words[i] | 0) - (b.words[i] | 0) + carry;

      carry = r >> 26;

      this.words[i] = r & 0x3ffffff;
    }

    for (; carry !== 0 && i < a.length; i++) {
      const r = (a.words[i] | 0) + carry;

      carry = r >> 26;

      this.words[i] = r & 0x3ffffff;
    }

    assert(carry === 0);

    // Copy rest of the words.
    if (a !== this) {
      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = Math.max(this.length, i);

    return this._strip();
  }

  _isubn(num) {
    this.words[0] -= num;

    if (this.words[0] >= 0)
      return this._normalize();

    assert(this.length !== 1);

    // Carry.
    this._alloc(this.length + 1);

    for (let i = 0; i < this.length && this.words[i] < 0; i++) {
      this.words[i] += 0x4000000;
      this.words[i + 1] -= 1;
    }

    this.words[this.length] = 0;

    return this._strip();
  }

  /*
   * Subtraction
   */

  isub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.negative !== num.negative) {
      // x - (-y) == x + y
      // (-x) - y == -(x + y)
      this._iadd(this, num);
    } else {
      // x - y == x - y == -(y - x)
      // (-x) - (-y) == y - x == -(x - y)
      const cmp = this.ucmp(num);

      // x - x == 0
      if (cmp === 0) {
        this.words[0] = 0;
        this.length = 1;
        this.negative = 0;
        return this;
      }

      if (cmp < 0) {
        this._isub(num, this);
        this.negative ^= 1;
      } else {
        this._isub(this, num);
      }
    }

    return this;
  }

  isubn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const negative = (num < 0) | 0;

    if (negative)
      num = -num;

    if (this.negative !== negative) {
      // x - (-y) == x + y
      // (-x) - y == -(x + y)
      this._iaddn(num);
    } else {
      // x - y == x - y == -(y - x)
      // (-x) - (-y) == y - x == -(x - y)
      if (this.length === 1 && this.words[0] < num) {
        this.words[0] = num - this.words[0];
        this.negative ^= 1;
      } else {
        this._isubn(num);
      }
    }

    return this;
  }

  sub(num) {
    return this.clone().isub(num);
  }

  subn(num) {
    return this.clone().isubn(num);
  }

  /*
   * Multiplication Engine
   */

  _mul(num, out) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce(BN.isBN(out), 'out', 'bignum');

    if (this.length === 10 && num.length === 10)
      return comb10MulTo(this, num, out);

    const len = this.length + num.length;

    if (len < 63)
      return smallMulTo(this, num, out);

    if (len < 1024)
      return bigMulTo(this, num, out);

    return jumboMulTo(this, num, out);
  }

  /*
   * Multiplication
   */

  imul(num) {
    return this.mul(num)._move(this);
  }

  imuln(num) {
    enforce(isSMI(num), 'num', 'smi');

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    // Carry.
    let carry = 0;

    for (let i = 0; i < this.length; i++) {
      const w = this.words[i] * num;
      const lo = (w & 0x3ffffff) + (carry & 0x3ffffff);

      carry >>= 26;
      carry += (w / 0x4000000) | 0;
      carry += lo >>> 26;

      this.words[i] = lo & 0x3ffffff;
    }

    this.negative ^= neg;

    if (carry !== 0) {
      this._alloc(this.length + 1);
      this.words[this.length++] = carry;
    } else {
      this._strip();
    }

    return this;
  }

  mul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const len = this.length + num.length;
    const out = new BN();

    out.words = new Array(len);

    for (let i = 0; i < len; i ++)
      out.words[i] = 0;

    return this._mul(num, out);
  }

  muln(num) {
    return this.clone().imuln(num);
  }

  /*
   * Multiplication + Shift
   */

  mulShift(num, bits) {
    enforce(BN.isBN(num), 'num', 'bignum');
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    const r = this.mul(num);
    const b = r.utestn(bits - 1);

    r.iushrn(bits);

    if (this.negative ^ num.negative)
      return r.isubn(b);

    return r.iaddn(b);
  }

  /*
   * Division Engine
   */

  _div(num, flags) {
    enforce(BN.isBN(num), 'num', 'bignum');
    assert((flags & modes.ALL) === flags);
    assert(flags !== modes.NONE);

    const a = this;
    const b = num;

    nonzero(!b.isZero());

    if (a.isZero())
      return [new BN(0), new BN(0)];

    const as = a.negative;
    const bs = b.negative;

    a.negative = 0;
    b.negative = 0;

    let q = null;
    let r = null;

    if (a.ucmp(b) < 0) {
      if (flags & modes.QUO)
        q = new BN(0);

      if (flags & modes.REM)
        r = a.clone();
    } else if (b.length === 1) {
      if (flags & modes.QUO)
        q = a.quon(b.words[0]);

      if (flags & modes.REM)
        r = a.remn(b.words[0]);
    } else {
      [q, r] = a._wordDiv(b, flags);
    }

    a.negative = as;
    b.negative = bs;

    if (flags & modes.QUO) {
      q.negative = a.negative ^ b.negative;
      q._normalize();
    }

    if (flags & modes.REM) {
      r.negative = a.negative;
      r._normalize();
    }

    if (flags & modes.EUCLID) {
      if (flags & modes.QUO) {
        assert((flags & modes.REM) !== 0);

        if (r.negative !== 0) {
          if (b.negative !== 0)
            q.iaddn(1);
          else
            q.isubn(1);
        }
      }

      if (flags & modes.REM) {
        if (r.negative !== 0) {
          if (b.negative !== 0)
            r.isub(b);
          else
            r.iadd(b);
        }
      }
    }

    return [q, r];
  }

  _wordDiv(num, flags) {
    let a = this.clone();
    let b = num;
    let q = null;
    let hi;

    // Normalize.
    const word = b.words[b.length - 1] | 0;
    const shift = 26 - countBits(word);

    if (shift !== 0) {
      b = b.clone();

      a.iushln(shift);
      b.iushln(shift);

      hi = b.words[b.length - 1] | 0;
    } else {
      hi = word;
    }

    // Initialize quotient.
    const m = a.length - b.length;

    assert(m >= 0);

    if (flags & modes.QUO) {
      q = new BN(0);
      q.length = m + 1;
      q.words = new Array(q.length);

      for (let i = 0; i < q.length; i++)
        q.words[i] = 0;
    }

    // Diff.
    const d = a.clone();

    d._ishlnsubmul(b, 1, m);

    if (d.negative === 0) {
      if (q)
        q.words[m] = 1;

      a = d;
    }

    // Divide.
    for (let j = m - 1; j >= 0; j--) {
      const ahi = a.words[b.length + j];
      const alo = a.words[b.length + j - 1];
      const quo = ((ahi * 0x4000000 + alo) / hi) | 0;

      let qj = Math.min(quo, 0x3ffffff);

      a._ishlnsubmul(b, qj, j);

      while (a.negative !== 0) {
        qj -= 1;
        a.negative = 0;
        a._ishlnsubmul(b, 1, j);
        a.ineg();
      }

      if (q)
        q.words[j] = qj;
    }

    // Strip.
    if (q)
      q._strip();

    // Denormalize.
    // Note: we shouldn't need to strip `a` here.
    if ((flags & modes.REM) && shift !== 0)
      a.iushrn(shift);

    return [q, a];
  }

  _ishlnsubmul(num, mul, shift) {
    let carry = 0;
    let i = 0;

    this._expand(num.length + shift);

    for (; i < num.length; i++) {
      const k = (this.words[i + shift] | 0) + carry;
      const r = num.words[i] * mul;
      const w = k - (r & 0x3ffffff);

      carry = (w >> 26) - ((r / 0x4000000) | 0);

      this.words[i + shift] = w & 0x3ffffff;
    }

    for (; i < this.length - shift; i++) {
      const w = (this.words[i + shift] | 0) + carry;

      carry = w >> 26;

      this.words[i + shift] = w & 0x3ffffff;
    }

    if (carry === 0)
      return this._strip();

    // Subtraction overflow.
    assert(carry === -1);

    carry = 0;

    for (let i = 0; i < this.length; i++) {
      const w = -(this.words[i] | 0) + carry;

      carry = w >> 26;

      this.words[i] = w & 0x3ffffff;
    }

    this.negative = 1;

    return this._strip();
  }

  /*
   * Truncation Division + Modulo
   */

  quorem(num) {
    return this._div(num, modes.BOTH);
  }

  /*
   * Truncation Division
   */

  iquo(num) {
    return this.quo(num)._move(this);
  }

  iquon(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    let carry = 0;

    for (let i = this.length - 1; i >= 0; i--) {
      const w = (this.words[i] | 0) + carry * 0x4000000;

      this.words[i] = (w / num) | 0;

      carry = w % num;
    }

    this.negative ^= neg;

    return this._strip();
  }

  quo(num) {
    return this._div(num, modes.QUO)[0];
  }

  quon(num) {
    return this.clone().iquon(num);
  }

  /*
   * Truncation Modulo
   */

  irem(num) {
    return this.rem(num)._move(this);
  }

  iremn(num) {
    let m = this.remrn(num);

    if (m < 0)
      m = -m;

    this.words[0] = m;
    this.length = 1;

    return this._normalize();
  }

  rem(num) {
    return this._div(num, modes.REM)[1];
  }

  remn(num) {
    return this.clone().iremn(num);
  }

  remrn(num) {
    enforce(isSMI(num), 'num', 'smi');
    nonzero(num !== 0);

    if (num < 0)
      num = -num;

    const p = (1 << 26) % num;

    let acc = 0;

    for (let i = this.length - 1; i >= 0; i--)
      acc = (p * acc + (this.words[i] | 0)) % num;

    return this.negative !== 0 ? (-acc | 0) : acc;
  }

  /*
   * Euclidean Division + Modulo
   */

  divmod(num) {
    return this._div(num, modes.BOTH | modes.EUCLID);
  }

  /*
   * Euclidean Division
   */

  idiv(num) {
    return this.div(num)._move(this);
  }

  idivn(num) {
    if (this.negative === 0)
      return this.iquon(num);

    const r = this.remrn(num);

    this.iquon(num);

    if (r < 0) {
      if (num < 0)
        this.iaddn(1);
      else
        this.isubn(1);
    }

    return this;
  }

  div(num) {
    return this._div(num, modes.BOTH | modes.EUCLID)[0];
  }

  divn(num) {
    return this.clone().idivn(num);
  }

  /*
   * Euclidean Modulo
   */

  imod(num) {
    if (this.ucmp(num) < 0) {
      if (this.negative !== 0) {
        this._isub(num, this);
        this.negative = 0;
      }
      return this;
    }

    return this.mod(num)._move(this);
  }

  imodn(num) {
    this.words[0] = this.modrn(num);
    this.length = 1;
    this.negative = 0;
    return this;
  }

  mod(num) {
    return this._div(num, modes.REM | modes.EUCLID)[1];
  }

  modn(num) {
    return this.clone().imodn(num);
  }

  modrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    let r = this.remrn(num);

    if (r < 0) {
      if (num < 0)
        r -= num;
      else
        r += num;
    }

    return r;
  }

  /*
   * Round Division
   */

  divRound(num) {
    const [q, r] = this.quorem(num);

    // Fast case - exact division.
    if (r.isZero())
      return q;

    const bit = num.words[0] & 1;

    num.iushrn(1);

    const cmp = r.ucmp(num);

    num.iushln(1);

    num.words[0] |= bit;

    // Round down.
    if (cmp < 0 || (num.isOdd() && cmp === 0))
      return q;

    // Round up.
    if (this.negative ^ num.negative)
      return q.isubn(1);

    return q.iaddn(1);
  }

  /*
   * Exponentiation
   */

  ipow(num) {
    return this.pow(num)._move(this);
  }

  ipown(num) {
    return this.pown(num)._move(this);
  }

  pow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let b = countBits(num.words[num.length - 1]);
    let r = new BN(1);

    for (let i = num.length - 1; i >= 0; i--) {
      const word = num.words[i];

      for (let j = b - 1; j >= 0; j--) {
        r = r.sqr();

        if ((word >> j) & 1)
          r = r.mul(this);
      }

      b = 26;
    }

    return r;
  }

  pown(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (num < 0)
      num = -num;

    if (num === 0)
      return new BN(1);

    if (num === 1)
      return this.clone();

    const bits = countBits(num);

    let r = this;

    for (let i = bits - 2; i >= 0; i--) {
      r = r.sqr();

      if ((num >> i) & 1)
        r = r.mul(this);
    }

    return r;
  }

  isqr() {
    return this.imul(this);
  }

  sqr() {
    return this.mul(this);
  }

  /*
   * Roots Engine
   */

  _rootrem(pow, rem) {
    enforce((pow >>> 0) === pow, 'num', 'uint32');

    if (pow === 0)
      throw new RangeError('Zeroth root.');

    if (~pow & this.negative)
      throw new RangeError('Negative with even root.');

    if (this.ucmpn(1) <= 0)
      return [this.clone(), new BN(0)];

    let u = new BN(0);
    let t = BN.shift(1, this.bitLength() / pow + 1 | 0);
    let v, r;

    if (this.negative !== 0)
      t.ineg();

    if (pow === 2) {
      do {
        u = t;
        t = this.quo(u);
        t.iadd(u);
        t.iushrn(1);
      } while (t.ucmp(u) < 0);
    } else {
      do {
        u = t;
        t = u.pown(pow - 1);
        t = this.quo(t);
        v = u.muln(pow - 1);
        t.iadd(v);
        t = t.quon(pow);
      } while (t.ucmp(u) < 0);
    }

    if (rem) {
      t = u.pown(pow);
      r = this.sub(t);
    }

    return [u, r];
  }

  /*
   * Roots
   */

  rootrem(pow) {
    return this._rootrem(pow, 1);
  }

  iroot(pow) {
    return this.root(pow)._move(this);
  }

  root(pow) {
    return this._rootrem(pow, 0)[0];
  }

  isPower(pow) {
    enforce((pow >>> 0) === pow, 'num', 'uint32');

    if (pow === 0 || (~pow & this.negative))
      return false;

    const [, r] = this.rootrem(pow);

    return r.sign() === 0;
  }

  sqrtrem() {
    return this.rootrem(2);
  }

  isqrt() {
    return this.sqrt()._move(this);
  }

  sqrt() {
    return this.root(2);
  }

  isSquare() {
    return this.isPower(2);
  }

  /*
   * AND
   */

  iand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let x = this;
    let y = num;

    if (x === y)
      return x;

    if ((x.negative | y.negative) === 0)
      return x.iuand(y);

    if ((x.negative & y.negative) === 1) {
      // (-x) & (-y) == ~(x-1) & ~(y-1)
      //             == ~((x-1) | (y-1))
      //             == -(((x-1) | (y-1)) + 1)
      x.iaddn(1);
      y.iaddn(1);
      x.iuor(y);
      x.isubn(1);
      y.isubn(1);
      return x;
    }

    // Assume x is the positive number.
    if (x.negative !== 0)
      [x, y] = [y.clone(), x];

    // x & (-y) == x & ~(y-1)
    //          == x & ~(y-1)
    const width = x.bitLength();

    y.iaddn(1);
    y.inotn(width);
    x.iuand(y);
    y.inotn(width);
    y.isubn(1);

    return x._move(this);
  }

  iandn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0)
      return this.iand(new BN(num));

    this.words[0] &= num;
    this.length = 1;

    return this;
  }

  and(num) {
    return this.clone().iand(num);
  }

  andn(num) {
    return this.clone().iandn(num);
  }

  andrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0) {
      const n = this.iand(new BN(num));

      if (n.length > 1)
        throw new RangeError('Number exceeds 26 bits.');

      return n.negative !== 0 ? -n.words[0] : n.words[0];
    }

    return this.words[0] & num;
  }

  /*
   * Unsigned AND
   */

  iuand(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this.length = Math.min(this.length, num.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] &= num.words[i];

    return this._strip();
  }

  iuandn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] &= Math.abs(num);
    this.length = 1;

    return this._normalize();
  }

  uand(num) {
    return this.clone().iuand(num);
  }

  uandn(num) {
    return this.clone().iuandn(num);
  }

  uandrn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const n = this.words[0] & Math.abs(num);

    return this.negative !== 0 ? (-n | 0) : n;
  }

  /*
   * OR
   */

  ior(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let x = this;
    let y = num;

    if (x === y)
      return x;

    if ((x.negative | y.negative) === 0)
      return x.iuor(y);

    if ((x.negative & y.negative) === 1) {
      // (-x) | (-y) == ~(x-1) | ~(y-1)
      //             == ~((x-1) & (y-1))
      //             == -(((x-1) & (y-1)) + 1)
      x.iaddn(1);
      y.iaddn(1);
      x.iuand(y);
      x.isubn(1);
      y.isubn(1);
      return x;
    }

    // Assume x is the positive number.
    y = y.clone();

    if (x.negative !== 0)
      [x, y] = [y, x];

    // x | (-y) == x | ~(y-1)
    //          == ~((y-1) & ~x)
    //          == -(((y-1) & ~x) + 1)
    y.iaddn(1);
    x.inotn(y.bitLength());
    y.iuand(x);
    y.isubn(1);

    return y._move(this);
  }

  iorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0)
      return this.ior(new BN(num));

    this.words[0] |= num;

    return this;
  }

  or(num) {
    return this.clone().ior(num);
  }

  orn(num) {
    return this.clone().iorn(num);
  }

  /*
   * Unsigned OR
   */

  iuor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this._expand(num.length);

    for (let i = 0; i < num.length; i++)
      this.words[i] |= num.words[i];

    // Note: we shouldn't need to strip here.
    return this;
  }

  iuorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] |= Math.abs(num);

    return this;
  }

  uor(num) {
    return this.clone().iuor(num);
  }

  uorn(num) {
    return this.clone().iuorn(num);
  }

  /*
   * XOR
   */

  ixor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let x = this;
    let y = num;

    if (x === y) {
      x.words[0] = 0;
      x.length = 1;
      x.negative = 0;
      return x;
    }

    if ((x.negative | y.negative) === 0)
      return x.iuxor(y);

    if ((x.negative & y.negative) === 1) {
      // (-x) ^ (-y) == ~(x-1) ^ ~(y-1)
      //             == (x-1) ^ (y-1)
      x.iaddn(1);
      y.iaddn(1);
      x.iuxor(y);
      x.ineg();
      y.isubn(1);
      return x;
    }

    // Assume x is the positive number.
    if (x.negative !== 0)
      [x, y] = [y.clone(), x];

    // x ^ (-y) == x ^ ~(y-1)
    //          == ~(x ^ (y-1))
    //          == -((x ^ (y-1)) + 1)
    y.iaddn(1);
    x.iuxor(y);
    x.iaddn(1);
    x.ineg();
    y.isubn(1);

    return x._move(this);
  }

  ixorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if ((this.negative | (num < 0)) !== 0)
      return this.ixor(new BN(num));

    this.words[0] ^= num;

    return this;
  }

  xor(num) {
    return this.clone().ixor(num);
  }

  xorn(num) {
    return this.clone().ixorn(num);
  }

  /*
   * Unsigned XOR
   */

  iuxor(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    let a = this;
    let b = num;

    if (a.length < b.length)
      [a, b] = [b, a];

    let i = 0;

    for (; i < b.length; i++)
      this.words[i] = a.words[i] ^ b.words[i];

    if (a !== this) {
      this._alloc(a.length);

      for (; i < a.length; i++)
        this.words[i] = a.words[i];
    }

    this.length = a.length;

    return this._strip();
  }

  iuxorn(num) {
    enforce(isSMI(num), 'num', 'smi');

    this.words[0] ^= Math.abs(num);

    return this._normalize();
  }

  uxor(num) {
    return this.clone().iuxor(num);
  }

  uxorn(num) {
    return this.clone().iuxorn(num);
  }

  /*
   * NOT
   */

  inot() {
    if (this.negative !== 0) {
      // ~(-x) == ~(~(x-1)) == x-1
      this.ineg().isubn(1);
    } else {
      // ~x == -x-1 == -(x+1)
      this.iaddn(1).ineg();
    }
    return this;
  }

  not() {
    return this.clone().inot();
  }

  inotn(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');

    const r = width % 26;

    let s = Math.ceil(width / 26);
    let i = 0;

    // Extend the buffer with leading zeroes.
    this._expand(s);

    if (r > 0)
      s -= 1;

    // Handle complete words.
    for (; i < s; i++)
      this.words[i] ^= 0x3ffffff;

    // Handle the residue.
    if (r > 0)
      this.words[i] ^= (1 << r) - 1;

    // And remove leading zeroes.
    return this._strip();
  }

  notn(width) {
    return this.clone().inotn(width);
  }

  /*
   * Left Shift
   */

  ishl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.ishln(num.toNumber());
  }

  ishln(bits) {
    return this.iushln(bits);
  }

  shl(num) {
    return this.clone().ishl(num);
  }

  shln(bits) {
    return this.clone().ishln(bits);
  }

  /*
   * Unsigned Left Shift
   */

  iushl(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.iushln(num.toNumber());
  }

  iushln(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    const r = bits % 26;
    const s = (bits - r) / 26;
    const mask = ((1 << r) - 1) << (26 - r);

    if (r !== 0) {
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const ncarry = this.words[i] & mask;
        const c = ((this.words[i] | 0) - ncarry) << r;

        this.words[i] = c | carry;

        carry = ncarry >>> (26 - r);
      }

      if (carry !== 0) {
        this._alloc(this.length + 1);
        this.words[this.length++] = carry;
      }
    }

    if (s !== 0) {
      this._alloc(this.length + s);

      for (let i = this.length - 1; i >= 0; i--)
        this.words[i + s] = this.words[i];

      for (let i = 0; i < s; i++)
        this.words[i] = 0;

      this.length += s;
    }

    return this._strip();
  }

  ushl(num) {
    return this.clone().iushl(num);
  }

  ushln(bits) {
    return this.clone().iushln(bits);
  }

  /*
   * Right Shift Engine
   */

  _split(bits, output) {
    const r = bits % 26;
    const s = Math.min((bits - r) / 26, this.length);
    const mask = (1 << r) - 1;

    // Extended mode, copy masked part.
    if (output) {
      output._alloc(s);

      for (let i = 0; i < s; i++)
        output.words[i] = this.words[i];

      output.length = s;
    }

    if (s === 0) {
      // No-op, we should not move anything at all.
    } else if (this.length > s) {
      this.length -= s;
      for (let i = 0; i < this.length; i++)
        this.words[i] = this.words[i + s];
    } else {
      this.words[0] = 0;
      this.length = 1;
    }

    let carry = 0;

    if (r !== 0) {
      for (let i = this.length - 1; i >= 0; i--) {
        const word = this.words[i] | 0;

        this.words[i] = (carry << (26 - r)) | (word >>> r);

        carry = word & mask;
      }
    }

    // Push carried bits as a mask.
    if (output) {
      if (carry !== 0) {
        output._alloc(output.length + 1);
        output.words[output.length++] = carry;
      } else {
        if (output.length === 0)
          output.words[output.length++] = 0;

        output._strip();
      }
    }

    return this._strip();
  }

  /*
   * Right Shift
   */

  ishr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.ishrn(num.toNumber());
  }

  ishrn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    if (this.negative !== 0) {
      // (-x) >> y == ~(x-1) >> y
      //           == ~((x-1) >> y)
      //           == -(((x-1) >> y) + 1)
      this.iaddn(1);
      this.iushrn(bits);
      this.isubn(1);
      return this;
    }

    return this.iushrn(bits);
  }

  shr(num) {
    return this.clone().ishr(num);
  }

  shrn(bits) {
    return this.clone().ishrn(bits);
  }

  /*
   * Unsigned Right Shift
   */

  iushr(num) {
    enforce(BN.isBN(num), 'bits', 'bignum');
    enforce(num.bitLength() <= 32, 'bits', 'uint32');
    return this.iushrn(num.toNumber());
  }

  iushrn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');
    return this._split(bits, null);
  }

  ushr(num) {
    return this.clone().iushr(num);
  }

  ushrn(bits) {
    return this.clone().iushrn(bits);
  }

  /*
   * Bit Manipulation
   */

  setn(bit, val) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    if (this.negative !== 0) {
      this.iaddn(1);
      this.usetn(bit, !val);
      this.isubn(1);
      return this;
    }

    return this.usetn(bit, val);
  }

  usetn(bit, val) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    const r = bit % 26;
    const s = (bit - r) / 26;

    this._expand(s + 1);

    if (val)
      this.words[s] |= (1 << r);
    else
      this.words[s] &= ~(1 << r);

    return this._strip();
  }

  testn(bit) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    const r = bit % 26;
    const s = (bit - r) / 26;

    // Fast case: bit is much higher than all existing words.
    if (this.length <= s)
      return this.negative;

    // Check bit and return.
    const w = this.words[s];
    const val = (w >> r) & 1;

    if (this.negative !== 0) {
      if (r > 0 && (w & ((1 << r) - 1)))
        return val ^ 1;

      let j = s;

      while (j--) {
        if (this.words[j] > 0)
          return val ^ 1;
      }
    }

    return val;
  }

  utestn(bit) {
    enforce((bit >>> 0) === bit, 'bit', 'uint32');

    const r = bit % 26;
    const s = (bit - r) / 26;

    // Fast case: bit is much higher than all existing words.
    if (this.length <= s)
      return 0;

    // Check bit and return.
    return (this.words[s] >> r) & 1;
  }

  imaskn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    if (this.negative !== 0) {
      this.iaddn(1);
      this.inotn(bits + 1);
      this.ineg();
    }

    return this.iumaskn(bits);
  }

  maskn(bits) {
    return this.clone().imaskn(bits);
  }

  iumaskn(bits) {
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    const r = bits % 26;

    let s = (bits - r) / 26;

    if (this.length <= s)
      return this;

    if (r !== 0)
      s += 1;

    this.length = Math.min(s, this.length);

    if (r !== 0)
      this.words[this.length - 1] &= (1 << r) - 1;

    if (this.length === 0)
      this.words[this.length++] = 0;

    return this._strip();
  }

  umaskn(bits) {
    return this.clone().iumaskn(bits);
  }

  andln(num) {
    return this.words[0] & num;
  }

  bit(pos) {
    return this.utestn(pos);
  }

  bits(pos, width) {
    enforce((pos >>> 0) === pos, 'pos', 'uint32');
    enforce((width >>> 0) === width, 'width', 'uint32');
    enforce(width <= 26, 'width', 'width');

    const shift = pos % 26;
    const index = (pos - shift) / 26;

    if (index >= this.length)
      return 0;

    let bits = (this.words[index] >> shift) & ((1 << width) - 1);

    if (shift + width > 26 && index + 1 < this.length) {
      const more = shift + width - 26;
      const next = this.words[index + 1] & ((1 << more) - 1);

      bits |= next << (26 - shift);
    }

    return bits;
  }

  /*
   * Negation
   */

  ineg() {
    if (!this.isZero())
      this.negative ^= 1;

    return this;
  }

  neg() {
    return this.clone().ineg();
  }

  iabs() {
    this.negative = 0;
    return this;
  }

  abs() {
    return this.clone().iabs();
  }

  /*
   * Comparison
   */

  cmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.negative !== num.negative)
      return num.negative - this.negative;

    const res = this.ucmp(num);

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  cmpn(num) {
    enforce(isSMI(num), 'num', 'smi');

    const negative = (num < 0) | 0;

    if (this.negative !== negative)
      return negative - this.negative;

    const res = this.ucmpn(num);

    if (this.negative !== 0)
      return -res | 0;

    return res;
  }

  eq(num) {
    return this.cmp(num) === 0;
  }

  eqn(num) {
    return this.cmpn(num) === 0;
  }

  gt(num) {
    return this.cmp(num) > 0;
  }

  gtn(num) {
    return this.cmpn(num) > 0;
  }

  gte(num) {
    return this.cmp(num) >= 0;
  }

  gten(num) {
    return this.cmpn(num) >= 0;
  }

  lt(num) {
    return this.cmp(num) < 0;
  }

  ltn(num) {
    return this.cmpn(num) < 0;
  }

  lte(num) {
    return this.cmp(num) <= 0;
  }

  lten(num) {
    return this.cmpn(num) <= 0;
  }

  sign() {
    if (this.negative !== 0)
      return -1;

    if (this.length === 1 && this.words[0] === 0)
      return 0;

    return 1;
  }

  isZero() {
    return this.length === 1 && this.words[0] === 0;
  }

  isNeg() {
    return this.negative !== 0;
  }

  isPos() {
    return this.negative === 0;
  }

  isOdd() {
    return (this.words[0] & 1) === 1;
  }

  isEven() {
    return (this.words[0] & 1) === 0;
  }

  /*
   * Unsigned Comparison
   */

  ucmp(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.length < num.length)
      return -1;

    if (this.length > num.length)
      return 1;

    for (let i = this.length - 1; i >= 0; i--) {
      const a = this.words[i] | 0;
      const b = num.words[i] | 0;

      if (a === b)
        continue;

      return (a > b) - (a < b);
    }

    return 0;
  }

  ucmpn(num) {
    enforce(isSMI(num), 'num', 'smi');

    if (this.length > 1)
      return 1;

    const w = this.words[0] | 0;

    if (num < 0)
      num = -num;

    return (w > num) - (w < num);
  }

  /*
   * Number Theoretic Functions
   */

  legendre(num) {
    const red = HAS_BIGINT ? BN.red(num) : BN.mont(num);
    return this.toRed(red).redLegendre();
  }

  jacobi(num) {
    // See: A Binary Algorithm for the Jacobi Symbol
    //   J. Shallit, J. Sorenson
    //   Page 3, Section 3
    enforce(BN.isBN(num), 'num', 'bignum');

    if (num.isZero() || num.isEven())
      throw new Error('jacobi: `num` must be odd.');

    let a = this._cloneNormal();
    let b = num.clone();
    let j = 1;

    if (b.isNeg()) {
      if (a.isNeg())
        j = -1;
      b.ineg();
    }

    if (a.isNeg() || a.ucmp(b) >= 0)
      a.imod(b);

    while (!a.isZero()) {
      const bits = a._makeOdd();

      if (bits & 1) {
        const bmod8 = b.andln(7);

        if (bmod8 === 3 || bmod8 === 5)
          j = -j;
      }

      if (a.ucmp(b) < 0) {
        [a, b] = [b, a];

        if (a.andln(3) === 3 && b.andln(3) === 3)
          j = -j;
      }

      a._isub(a, b).iushrn(1);

      const bmod8 = b.andln(7);

      if (bmod8 === 3 || bmod8 === 5)
        j = -j;
    }

    if (b.cmpn(1) !== 0)
      return 0;

    return j;
  }

  kronecker(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const table = [
      0,  1, 0, -1,
      0, -1, 0,  1
    ];

    let a = this._cloneNormal();
    let b = num.clone();
    let k = 1;

    if (b.isZero())
      return a.ucmpn(1) === 0 ? k : 0;

    if (!a.isOdd() && !b.isOdd())
      return 0;

    const bits = b._makeOdd();

    if (bits & 1)
      k = table[a.andln(7)];

    if (b.isNeg()) {
      if (a.isNeg())
        k = -k;
      b.ineg();
    }

    while (!a.isZero()) {
      const bits = a._makeOdd();

      if (bits & 1)
        k *= table[b.andln(7)];

      const w = a.words[0] ^ (a.negative * 0x3ffffff);

      if (w & b.words[0] & 2)
        k = -k;

      b.imod(a);

      [a, b] = [b, a];

      b.negative = 0;
    }

    if (b.cmpn(1) !== 0)
      return 0;

    return k;
  }

  igcd(num) {
    return this.gcd(num)._move(this);
  }

  gcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero())
      return num.abs();

    if (num.isZero())
      return this.abs();

    let a = this.clone();
    let b = num.clone();

    a.negative = 0;
    b.negative = 0;

    // Remove common factor of two.
    const shift = a._factor2(b);

    if (shift !== 0) {
      a.iushrn(shift);
      b.iushrn(shift);
    }

    for (;;) {
      a._makeOdd();
      b._makeOdd();

      const cmp = a.ucmp(b);

      if (cmp < 0) {
        // a > b
        [a, b] = [b, a];
      } else if (cmp === 0 || b.ucmpn(1) === 0) {
        // Break if a == b.
        // Break if b == 1 to avoid repeated subtraction.
        break;
      }

      a._isub(a, b);
    }

    return b.iushln(shift);
  }

  ilcm(num) {
    return this.lcm(num)._move(this);
  }

  lcm(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero() || num.isZero())
      return new BN(0);

    return this.quo(this.gcd(num)).mul(num).iabs();
  }

  egcd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    if (this.isZero()) {
      return [
        new BN(0),
        new BN(num.sign()),
        num.abs()
      ];
    }

    if (num.isZero()) {
      return [
        new BN(this.sign()),
        new BN(0),
        this.abs()
      ];
    }

    const x = this.clone();
    const y = num.clone();

    x.negative = 0;
    y.negative = 0;

    // A * x + B * y = x
    const A = new BN(1);
    const B = new BN(0);

    // C * x + D * y = y
    const C = new BN(0);
    const D = new BN(1);

    // Remove common factor of two.
    const g = x._factor2(y);

    if (g > 0) {
      x.iushrn(g);
      y.iushrn(g);
    }

    const xp = x.clone();
    const yp = y.clone();

    while (!x.isZero()) {
      let i = x._makeOdd();
      let j = y._makeOdd();

      while (i--) {
        if (A.isOdd() || B.isOdd()) {
          A.iadd(yp);
          B.isub(xp);
        }

        A.iushrn(1);
        B.iushrn(1);
      }

      while (j--) {
        if (C.isOdd() || D.isOdd()) {
          C.iadd(yp);
          D.isub(xp);
        }

        C.iushrn(1);
        D.iushrn(1);
      }

      if (x.cmp(y) >= 0) {
        x.isub(y);
        A.isub(C);
        B.isub(D);
      } else {
        y.isub(x);
        C.isub(A);
        D.isub(B);
      }
    }

    if (this.negative !== 0)
      C.ineg();

    if (num.negative !== 0)
      D.ineg();

    return [C, D, y.iushln(g)];
  }

  iinvert(num) {
    return this.invert(num)._move(this);
  }

  invert(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.sign() > 0, 'invert');

    if (num.isOdd())
      return this._invertp(num);

    if (num.cmpn(1) === 0)
      throw new RangeError('Not invertible.');

    const [s,, g] = this.egcd(num);

    if (g.cmpn(1) !== 0)
      throw new RangeError('Not invertible.');

    return s.imod(num);
  }

  ifermat(num) {
    return this.fermat(num)._move(this);
  }

  fermat(num) {
    const red = HAS_BIGINT ? BN.red(num) : BN.mont(num);
    return this.toRed(red).redFermat().fromRed();
  }

  ipowm(y, m, mont) {
    return this.powm(y, m, mont)._move(this);
  }

  powm(y, m, mont) {
    const red = !HAS_BIGINT && mont ? BN.mont(m) : BN.red(m);
    return this.toRed(red).redPow(y).fromRed();
  }

  ipowmn(y, m, mont) {
    return this.powmn(y, m, mont)._move(this);
  }

  powmn(y, m, mont) {
    const red = mont ? BN.mont(m) : BN.red(m);
    return this.toRed(red).redPown(y).fromRed();
  }

  isqrtm(p) {
    return this.sqrtm(p)._move(this);
  }

  sqrtm(p) {
    enforce(BN.isBN(p), 'p', 'bignum');

    let red;

    if (p.andln(3) === 3 || p.andln(7) === 5) {
      // Probably not worth the setup.
      red = BN.red(p);
    } else {
      red = BN.mont(p);
    }

    return this.toRed(red).redSqrt().fromRed();
  }

  isqrtpq(p, q) {
    return this.sqrtpq(p, q)._move(this);
  }

  sqrtpq(p, q) {
    const sp = this.sqrtm(p);
    const sq = this.sqrtm(q);
    const [mp, mq] = p.egcd(q);
    const lhs = sq.mul(mp).mul(p);
    const rhs = sp.mul(mq).mul(q);
    const n = p.mul(q);

    return lhs.iadd(rhs).imod(n);
  }

  /*
   * Primality Testing
   */

  isPrime(rng, reps, limit) {
    enforce((reps >>> 0) === reps, 'reps', 'uint32');

    if (!this.isPrimeMR(rng, reps + 1, true))
      return false;

    if (!this.isPrimeLucas(limit))
      return false;

    return true;
  }

  isPrimeMR(rng, reps, force2 = false) {
    enforce((reps >>> 0) === reps, 'reps', 'uint32');
    enforce(reps > 0, 'reps', 'integer');
    enforce(typeof force2 === 'boolean', 'force2', 'boolean');

    const n = this;

    if (n.cmpn(7) < 0) {
      return n.cmpn(2) === 0
          || n.cmpn(3) === 0
          || n.cmpn(5) === 0;
    }

    if (n.isEven())
      return false;

    const nm1 = n.subn(1);
    const nm3 = nm1.subn(2);
    const k = nm1.zeroBits();
    const q = nm1.ushrn(k);

    const red = BN.red(n);
    const rnm1 = nm1.toRed(red);
    const rone = new BN(1).toRed(red);

next:
    for (let i = 0; i < reps; i++) {
      let x;

      if (i === reps - 1 && force2) {
        x = new BN(2);
      } else {
        x = BN.random(rng, 0, nm3);
        x.iaddn(2);
      }

      let y = x.toRed(red).redPow(q);

      if (y.cmp(rone) === 0 || y.cmp(rnm1) === 0)
        continue;

      for (let j = 1; j < k; j++) {
        y = y.redSqr();

        if (y.cmp(rnm1) === 0)
          continue next;

        if (y.cmp(rone) === 0)
          return false;
      }

      return false;
    }

    return true;
  }

  isPrimeLucas(limit = 0) {
    enforce((limit >>> 0) === limit, 'limit', 'uint32');

    const n = this;

    // Ignore 0 and 1.
    if (n.cmpn(1) <= 0)
      return false;

    // Two is the only even prime.
    if (n.isEven())
      return n.cmpn(2) === 0;

    let p = 3;

    for (;;) {
      if (p > 10000) {
        // Thought to be impossible.
        throw new Error(`Cannot find (D/n) = -1 for ${n.toString(10)}.`);
      }

      if (limit !== 0 && p > limit) {
        // Optional DoS limit.
        return false;
      }

      const d = new BN(p * p - 4);
      const j = d.jacobi(n);

      if (j === -1)
        break;

      if (j === 0)
        return n.cmpn(p + 2) === 0;

      if (p === 40) {
        if (n.isSquare())
          return false;
      }

      p += 1;
    }

    const s = n.addn(1);
    const r = s._makeOdd();

    let vk = new BN(2);
    let vk1 = new BN(p);

    for (let i = s.bitLength(); i >= 0; i--) {
      if (s.utestn(i)) {
        vk = vk.mul(vk1).isubn(p).imod(n);
        vk1 = vk1.sqr().isubn(2).imod(n);
      } else {
        vk1 = vk1.mul(vk).isubn(p).imod(n);
        vk = vk.sqr().isubn(2).imod(n);
      }
    }

    if (vk.cmpn(2) === 0 || vk.cmp(n.subn(2)) === 0) {
      const a = vk.muln(p).imod(n);
      const b = vk1.ushln(1).imod(n);

      if (a.cmp(b) === 0)
        return true;
    }

    for (let t = 0; t < r - 1; t++) {
      if (vk.isZero())
        return true;

      if (vk.cmpn(2) === 0)
        return false;

      vk = vk.sqr().isubn(2).imod(n);
    }

    return false;
  }

  /*
   * Twos Complement
   */

  toTwos(width) {
    if (this.negative !== 0)
      return this.abs().inotn(width).iaddn(1);

    return this.clone();
  }

  fromTwos(width) {
    enforce((width >>> 0) === width, 'width', 'uint32');
    range(width > 0, 'width');

    if (this.testn(width - 1))
      return this.notn(width).iaddn(1).ineg();

    return this.clone();
  }

  /*
   * Reduction Context
   */

  toRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red)
      throw new Error('Already in reduction context.');

    return ctx.convertTo(this);
  }

  fromRed() {
    red(this.red, 'fromRed');
    return this.red.convertFrom(this);
  }

  forceRed(ctx) {
    enforce(ctx instanceof Red, 'ctx', 'reduction context');

    if (this.red) {
      if (!ctx.m.eq(this.red.m) || ctx.mont !== this.red.mont)
        throw new Error('Already in reduction context.');
    } else {
      range(this.negative === 0, 'red');
      range(this.ucmp(ctx.m) < 0, 'red');
    }

    return this.clone()._forceRed(ctx);
  }

  redIAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIAdd');
    return this.red.iadd(this, num);
  }

  redAdd(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redAdd');
    return this.red.add(this, num);
  }

  redIAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIAddn');
    return this.red.iaddn(this, num);
  }

  redAddn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redAddn');
    return this.red.addn(this, num);
  }

  redISub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redISub');
    return this.red.isub(this, num);
  }

  redSub(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redSub');
    return this.red.sub(this, num);
  }

  redISubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redISubn');
    return this.red.isubn(this, num);
  }

  redSubn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redSubn');
    return this.red.subn(this, num);
  }

  redIMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIMul');
    return this.red.imul(this, num);
  }

  redMul(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redMul');
    return this.red.mul(this, num);
  }

  redIMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIMuln');
    return this.red.imuln(this, num);
  }

  redMuln(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redMuln');
    return this.red.muln(this, num);
  }

  redIDiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIDiv');
    return this.red.idiv(this, num);
  }

  redDiv(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redDiv');
    return this.red.div(this, num);
  }

  redIDivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIDivn');
    return this.red.idivn(this, num);
  }

  redDivn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redDivn');
    return this.red.divn(this, num);
  }

  redIPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIPow');
    nonred(!num.red, 'redIPow');
    return this.red.ipow(this, num);
  }

  redPow(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redPow');
    nonred(!num.red, 'redPow');
    return this.red.pow(this, num);
  }

  redIPown(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redIPown');
    return this.red.ipown(this, num);
  }

  redPown(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redPown');
    return this.red.pown(this, num);
  }

  redISqr() {
    red(this.red, 'redISqr');
    return this.red.isqr(this);
  }

  redSqr() {
    red(this.red, 'redSqr');
    return this.red.sqr(this);
  }

  redISqrt() {
    red(this.red, 'redISqrt');
    return this.red.isqrt(this);
  }

  redSqrt() {
    red(this.red, 'redSqrt');
    return this.red.sqrt(this);
  }

  redIDivSqrt(v) {
    red(this.red, 'redIDivSqrt');
    return this.red.idivsqrt(this, v);
  }

  redDivSqrt(v) {
    red(this.red, 'redDivSqrt');
    return this.red.divsqrt(this, v);
  }

  redIsSquare() {
    red(this.red, 'redIsSquare');
    return this.red.isSquare(this);
  }

  redIShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redIShl');
    nonred(!num.red, 'redIShl');
    return this.red.ishl(this, num);
  }

  redShl(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redShl');
    nonred(!num.red, 'redShl');
    return this.red.shl(this, num);
  }

  redIShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redIShln');
    return this.red.ishln(this, num);
  }

  redShln(num) {
    enforce((num >>> 0) === num, 'num', 'uint32');
    red(this.red, 'redShln');
    return this.red.shln(this, num);
  }

  redINeg() {
    red(this.red, 'redINeg');
    return this.red.ineg(this);
  }

  redNeg() {
    red(this.red, 'redNeg');
    return this.red.neg(this);
  }

  redEq(num) {
    enforce(BN.isBN(num), 'num', 'bignum');
    red(this.red, 'redEq');
    return this.red.eq(this, num);
  }

  redEqn(num) {
    enforce(isSMI(num), 'num', 'smi');
    red(this.red, 'redEqn');
    return this.red.eqn(this, num);
  }

  redIsHigh() {
    red(this.red, 'redIsHigh');
    return this.red.isHigh(this);
  }

  redIsLow() {
    red(this.red, 'redIsLow');
    return this.red.isLow(this);
  }

  redIsOdd() {
    red(this.red, 'redIsOdd');
    return this.red.isOdd(this);
  }

  redIsEven() {
    red(this.red, 'redIsEven');
    return this.red.isEven(this);
  }

  redLegendre() {
    red(this.red, 'redLegendre');
    return this.red.legendre(this);
  }

  redJacobi() {
    red(this.red, 'redJacobi');
    return this.red.jacobi(this);
  }

  redKronecker() {
    red(this.red, 'redKronecker');
    return this.red.kronecker(this);
  }

  redIInvert() {
    red(this.red, 'redIInvert');
    return this.red.iinvert(this);
  }

  redInvert() {
    red(this.red, 'redInvert');
    return this.red.invert(this);
  }

  redIFermat() {
    red(this.red, 'redIFermat');
    return this.red.ifermat(this);
  }

  redFermat() {
    red(this.red, 'redFermat');
    return this.red.fermat(this);
  }

  /*
   * Internal
   */

  _move(dest) {
    dest.words = this.words;
    dest.length = this.length;
    dest.negative = this.negative;
    dest.red = this.red;
    return dest;
  }

  _alloc(size) {
    while (this.words.length < size)
      this.words.push(0);

    return this;
  }

  _expand(size) {
    this._alloc(size);

    while (this.length < size)
      this.words[this.length++] = 0;

    return this;
  }

  _strip() {
    while (this.length > 1 && this.words[this.length - 1] === 0)
      this.length -= 1;

    return this._normalize();
  }

  _normalize() {
    assert(this.length > 0);

    // -0 = 0
    if (this.length === 1 && this.words[0] === 0)
      this.negative = 0;

    return this;
  }

  _check() {
    // We never have a zero length number.
    assert(this.length > 0);

    // Cannot exceed array bounds.
    assert(this.length <= this.words.length);

    if (this.length === 1) {
      // Must be normalized.
      if (this.words[0] === 0)
        assert(this.negative === 0);
      return this;
    }

    // Must be stripped.
    assert(this.words[this.length - 1] !== 0);

    return this;
  }

  _invertp(p) {
    // Penk's right shift binary EGCD.
    //
    // See: The Art of Computer Programming,
    //      Volume 2, Seminumerical Algorithms
    //   Donald E. Knuth
    //   Exercise 4.5.2.39
    enforce(BN.isBN(p), 'p', 'bignum');
    range(p.sign() > 0, 'invert');
    assert(p.isOdd());

    if (p.cmpn(1) === 0)
      throw new RangeError('Not invertible.');

    const a = this.clone();
    const b = p.clone();
    const u = new BN(1);
    const v = new BN(0);

    if (a.isNeg() || a.ucmp(b) >= 0)
      a.imod(b);

    while (!a.isZero()) {
      let i = a._makeOdd();
      let j = b._makeOdd();

      while (i--) {
        if (u.isOdd())
          u._iadd(u, p);

        u.iushrn(1);
      }

      while (j--) {
        if (v.isOdd())
          v._iadd(v, p);

        v.iushrn(1);
      }

      if (a.ucmp(b) >= 0) {
        a._isub(a, b);
        if (u.ucmp(v) < 0) {
          u._isub(v, u);
          u._isub(p, u);
        } else {
          u._isub(u, v);
        }
      } else {
        b._isub(b, a);
        if (v.ucmp(u) < 0) {
          v._isub(u, v);
          v._isub(p, v);
        } else {
          v._isub(v, u);
        }
      }
    }

    if (b.cmpn(1) !== 0)
      throw new RangeError('Not invertible.');

    assert(v.negative === 0);
    assert(v.ucmp(p) < 0);

    return v;
  }

  _makeOdd() {
    const shift = this.zeroBits();

    if (shift > 0)
      this.iushrn(shift);

    return shift;
  }

  _factor2(num) {
    // Find common factor of two.
    // Expects inputs to be non-zero.
    if ((this.words[0] | num.words[0]) & 1)
      return 0;

    const len = Math.min(this.length, num.length);

    let r = 0;

    for (let i = 0; i < len; i++) {
      const b = zeroBits(this.words[i] | num.words[i]);

      r += b;

      if (b !== 26)
        break;
    }

    return r;
  }

  _cloneNormal() {
    return this.red ? this.fromRed() : this.clone();
  }

  _forceRed(ctx) {
    this.red = ctx;
    return this;
  }

  /*
   * Helpers
   */

  clone() {
    const copy = new BN();

    copy.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      copy.words[i] = this.words[i];

    copy.length = this.length;
    copy.negative = this.negative;
    copy.red = this.red;

    return copy;
  }

  inject(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    this._alloc(num.length);

    for (let i = 0; i < num.length; i++)
      this.words[i] = num.words[i];

    this.length = num.length;
    this.negative = num.negative;
    this.red = num.red;

    return this;
  }

  set(num, endian) {
    return this.fromNumber(num, endian);
  }

  swap(num) {
    enforce(BN.isBN(num), 'num', 'bignum');

    const x = this;
    const y = num;

    [x.words, y.words] = [y.words, x.words];
    [x.length, y.length] = [y.length, x.length];
    [x.negative, y.negative] = [y.negative, x.negative];
    [x.red, y.red] = [y.red, x.red];

    return x;
  }

  reverse() {
    const neg = this.negative;

    this.fromBuffer(this.toBuffer('be'), 'le');
    this.negative = neg;

    return this;
  }

  byteLength() {
    return Math.ceil(this.bitLength() / 8);
  }

  bitLength() {
    const w = this.words[this.length - 1];
    const hi = countBits(w);
    return (this.length - 1) * 26 + hi;
  }

  zeroBits() {
    if (this.isZero())
      return 0;

    if (this.isOdd())
      return 0;

    let r = 0;

    for (let i = 0; i < this.length; i++) {
      const b = zeroBits(this.words[i]);

      r += b;

      if (b !== 26)
        break;
    }

    return r;
  }

  isSafe() {
    if (this.length <= 2)
      return true;

    if (this.length === 3 && this.words[2] === 0x01)
      return true;

    return false;
  }

  word(pos) {
    enforce((pos >>> 0) === pos, 'pos', 'uint32');

    if (pos >= this.length)
      return 0;

    return this.words[pos];
  }

  [custom]() {
    let prefix = 'BN';

    if (this.red)
      prefix = 'BN-R';

    return `<${prefix}: ${this.toString(10)}>`;
  }

  /*
   * Conversion
   */

  toNumber() {
    let num = this.words[0];

    if (this.length === 2) {
      num += this.words[1] * 0x4000000;
    } else if (this.length === 3 && this.words[2] === 0x01) {
      // Note: at this stage it is known that the top bit is set.
      num += 0x10000000000000 + (this.words[1] * 0x4000000);
    } else if (this.length > 2) {
      throw new RangeError('Number can only safely store up to 53 bits.');
    }

    return this.negative !== 0 ? -num : num;
  }

  toDouble() {
    let num = 0;

    for (let i = this.length - 1; i >= 0; i--)
      num = (num * 0x4000000) + this.words[i];

    return this.negative !== 0 ? -num : num;
  }

  valueOf() {
    return this.toDouble();
  }

  toBigInt() {
    if (!HAS_BIGINT)
      throw new Error('BigInt is not supported!');

    const s52 = BigInt(52);
    const s26 = BigInt(26);

    let i = this.length - 1;
    let num = BigInt(0);

    for (; i >= 1; i -= 2) {
      const hi = this.words[i] * 0x4000000;
      const lo = this.words[i - 1];

      num = (num << s52) | BigInt(hi + lo);
    }

    if (i >= 0)
      num = (num << s26) | BigInt(this.words[0]);

    return this.negative !== 0 ? -num : num;
  }

  toBool() {
    return !this.isZero();
  }

  toString(base, padding) {
    base = getBase(base);

    if (padding == null)
      padding = 0;

    if (padding === 0)
      padding = 1;

    enforce((base >>> 0) === base, 'base', 'uint32');
    enforce((padding >>> 0) === padding, 'padding', 'uint32');

    if (base < 2 || base > 36)
      throw new RangeError('Base ranges between 2 and 36.');

    this._check();

    if (base === 16) {
      let out = '';
      let off = 0;
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const w = this.words[i];
        const word = (((w << off) | carry) & 0xffffff).toString(16);

        carry = (w >>> (24 - off)) & 0xffffff;

        if (carry !== 0 || i !== this.length - 1)
          out = zeros[6 - word.length] + word + out;
        else
          out = word + out;

        off += 2;

        if (off >= 26) {
          off -= 26;
          i -= 1;
        }
      }

      if (carry !== 0)
        out = carry.toString(16) + out;

      while (out.length % padding !== 0)
        out = '0' + out;

      if (this.negative !== 0)
        out = '-' + out;

      return out;
    }

    const groupSize = groupSizes[base - 1];
    const groupBase = groupBases[base - 1];
    const c = this.clone();

    let out = '';

    c.negative = 0;

    while (!c.isZero()) {
      const r = c.remrn(groupBase).toString(base);

      c.iquon(groupBase);

      if (!c.isZero())
        out = zeros[groupSize - r.length] + r + out;
      else
        out = r + out;
    }

    if (this.isZero())
      out = '0';

    while (out.length % padding !== 0)
      out = '0' + out;

    if (this.negative !== 0)
      out = '-' + out;

    return out;
  }

  toJSON() {
    return this.toString(16, 2);
  }

  toArray(endian, length) {
    return this.toArrayLike(Array, endian, length);
  }

  toBuffer(endian, length) {
    return this.toArrayLike(Buffer, endian, length);
  }

  toArrayLike(ArrayType, endian, length) {
    if (endian == null)
      endian = 'be';

    if (length == null)
      length = 0;

    enforce(typeof ArrayType === 'function', 'ArrayType', 'function');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');
    enforce((length >>> 0) === length, 'length', 'uint32');

    this._check();

    const bytes = this.byteLength();
    const size = length || Math.max(1, bytes);

    if (bytes > size)
      throw new RangeError('Byte array longer than desired length.');

    const res = allocate(ArrayType, size);

    // See: https://github.com/indutny/bn.js/pull/222
    if (endian === 'be') {
      let pos = res.length - 1;
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const shift = (i & 3) << 1;
        const word = (this.words[i] << shift) | carry;

        res[pos--] = word & 0xff;

        if (pos >= 0)
          res[pos--] = (word >>> 8) & 0xff;

        if (pos >= 0)
          res[pos--] = (word >>> 16) & 0xff;

        if (shift === 6) {
          if (pos >= 0)
            res[pos--] = (word >>> 24) & 0xff;

          carry = 0;
        } else {
          carry = word >>> 24;
        }
      }

      if (pos >= 0) {
        res[pos--] = carry;

        while (pos >= 0)
          res[pos--] = 0;

        carry = 0;
      }

      assert(carry === 0);
    } else {
      let pos = 0;
      let carry = 0;

      for (let i = 0; i < this.length; i++) {
        const shift = (i & 3) << 1;
        const word = (this.words[i] << shift) | carry;

        res[pos++] = word & 0xff;

        if (pos < res.length)
          res[pos++] = (word >>> 8) & 0xff;

        if (pos < res.length)
          res[pos++] = (word >>> 16) & 0xff;

        if (shift === 6) {
          if (pos < res.length)
            res[pos++] = (word >>> 24) & 0xff;

          carry = 0;
        } else {
          carry = word >>> 24;
        }
      }

      if (pos < res.length) {
        res[pos++] = carry;

        while (pos < res.length)
          res[pos++] = 0;

        carry = 0;
      }

      assert(carry === 0);
    }

    return res;
  }

  encode(endian, length) {
    return this.toBuffer(endian, length);
  }

  /*
   * Instantiation
   */

  of(num, endian) {
    return this.fromNumber(num, endian);
  }

  fromNumber(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(isInteger(num), 'num', 'integer');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    const neg = (num < 0) | 0;

    if (neg)
      num = -num;

    if (num < 0x4000000) {
      this.words[0] = num & 0x3ffffff;
      this.length = 1;
    } else if (num < 0x10000000000000) {
      this.words = [
        num & 0x3ffffff,
        (num / 0x4000000) & 0x3ffffff
      ];
      this.length = 2;
    } else {
      this.words = [
        num & 0x3ffffff,
        (num / 0x4000000) & 0x3ffffff,
        1
      ];
      this.length = 3;
    }

    this.negative = neg;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromDouble(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'number', 'num', 'double');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!isFinite(num))
      num = 0;

    const neg = (num <= -1) | 0;

    if (num < 0)
      num = -num;

    num = Math.floor(num);

    this.words = [];

    while (num > 0) {
      const lo = num % 0x4000000;
      const hi = (num - lo) / 0x4000000;

      this.words.push(lo);

      num = hi;
    }

    if (this.words.length === 0)
      this.words.push(0);

    this.length = this.words.length;
    this.negative = neg;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBigInt(num, endian) {
    if (endian == null)
      endian = 'be';

    enforce(typeof num === 'bigint', 'num', 'bigint');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (!HAS_BIGINT)
      throw new Error('BigInt is not supported!');

    // You know the implementation has a
    // problem when strings are twice
    // as fast as bigints.
    const start = (num < BigInt(0)) | 0;

    this._fromHex(num.toString(16), start);
    this.negative = start;

    if (endian === 'le')
      this.reverse();

    return this;
  }

  fromBool(value) {
    enforce(typeof value === 'boolean', 'value', 'boolean');

    this.words[0] = value | 0;
    this.length = 1;
    this.negative = 0;

    return this;
  }

  fromString(str, base, endian) {
    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    base = getBase(base);

    if (endian == null)
      endian = 'be';

    enforce(typeof str === 'string', 'string', 'string');
    enforce((base >>> 0) === base, 'base', 'uint32');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (base < 2 || base > 36)
      throw new Error('Base ranges between 2 and 36.');

    str = str.replace(/\s+/g, '');

    let start = 0;

    if (str.length > 0 && str.charCodeAt(0) === 0x2d)
      start = 1;

    if (base === 16)
      this._fromHex(str, start);
    else
      this._fromBase(str, base, start);

    this.negative = start;

    this._normalize();

    if (endian === 'le')
      this.reverse();

    return this;
  }

  _fromHex(str, start) {
    this.length = Math.max(2, Math.ceil((str.length - start) / 6));
    this.words = new Array(this.length);

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    // Scan 24-bit chunks and add them to the number.
    let off = 0;
    let i = str.length - 6;
    let j = 0;

    for (; i >= start; i -= 6) {
      const w = parseHex(str, i, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;

      // `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb.
      this.words[j + 1] |= (w >>> (26 - off)) & 0x3fffff;

      off += 24;

      if (off >= 26) {
        off -= 26;
        j += 1;
      }
    }

    if (i + 6 !== start) {
      const w = parseHex(str, start, i + 6);

      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] |= (w >>> (26 - off)) & 0x3fffff;
    }

    return this._strip();
  }

  _fromBase(str, base, start) {
    // Initialize as zero.
    this.words[0] = 0;
    this.length = 1;
    this.negative = 0;

    // Find length of limb in base.
    let limbLen = 0;
    let limbPow = 1;

    for (; limbPow <= 0x3ffffff; limbPow *= base)
      limbLen += 1;

    limbLen -= 1;
    limbPow = (limbPow / base) | 0;

    const total = str.length - start;
    const mod = total % limbLen;
    const end = Math.min(total, total - mod) + start;

    let i = start;

    for (; i < end; i += limbLen) {
      const word = parseBase(str, i, i + limbLen, base);

      this.imuln(limbPow);
      this._iaddn(word);
    }

    if (mod !== 0) {
      const pow = Math.pow(base, mod);
      const word = parseBase(str, i, str.length, base);

      this.imuln(pow);
      this._iaddn(word);
    }

    return this;
  }

  fromJSON(json) {
    if (BN.isBN(json)) {
      if (json.red)
        return json.fromRed();

      return json.clone();
    }

    if (Array.isArray(json)) {
      for (const chunk of json)
        enforce(typeof chunk === 'string', 'chunk', 'string');

      json = json.join('');
    }

    return this.fromString(json, 16);
  }

  fromBN(num) {
    return this.inject(num);
  }

  fromArray(data, endian) {
    enforce(Array.isArray(data), 'data', 'array');
    return this.fromArrayLike(data, endian);
  }

  fromBuffer(data, endian) {
    enforce(Buffer.isBuffer(data), 'data', 'buffer');
    return this.fromArrayLike(data, endian);
  }

  fromArrayLike(data, endian) {
    if (endian == null)
      endian = 'be';

    enforce(data && (data.length >>> 0) === data.length, 'data', 'array-like');
    enforce(endian === 'be' || endian === 'le', 'endian', 'endianness');

    if (data.length === 0) {
      this.words[0] = 0;
      this.length = 1;
      this.negative = 0;
      return this;
    }

    this.length = Math.max(2, Math.ceil(data.length / 3));
    this.words = new Array(this.length);
    this.negative = 0;

    for (let i = 0; i < this.length; i++)
      this.words[i] = 0;

    const left = data.length % 3;

    let off = 0;
    let j = 0;
    let w = 0;

    if (endian === 'be') {
      for (let i = data.length - 1; i >= 2; i -= 3) {
        const w = data[i] | (data[i - 1] << 8) | (data[i - 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j += 1;
        }
      }

      switch (left) {
        case 2:
          w = data[1] | (data[0] << 8);
          break;
        case 1:
          w = data[0];
          break;
      }
    } else {
      const len = data.length - left;

      for (let i = 0; i < len; i += 3) {
        const w = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16);

        this.words[j] |= (w << off) & 0x3ffffff;
        this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;

        off += 24;

        if (off >= 26) {
          off -= 26;
          j += 1;
        }
      }

      switch (left) {
        case 2:
          w = data[len] | (data[len + 1] << 8);
          break;
        case 1:
          w = data[len];
          break;
      }
    }

    if (left > 0) {
      this.words[j] |= (w << off) & 0x3ffffff;
      this.words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
    }

    return this._strip();
  }

  decode(data, endian) {
    return this.fromBuffer(data, endian);
  }

  from(num, base, endian) {
    if (num == null)
      return this;

    if (base === 'le' || base === 'be')
      [base, endian] = [endian, base];

    if (typeof num === 'number')
      return this.fromNumber(num, endian);

    if (typeof num === 'bigint')
      return this.fromBigInt(num, endian);

    if (typeof num === 'string')
      return this.fromString(num, base, endian);

    if (typeof num === 'object') {
      if (BN.isBN(num))
        return this.fromBN(num, endian);

      if ((num.length >>> 0) === num.length)
        return this.fromArrayLike(num, endian);
    }

    if (typeof num === 'boolean')
      return this.fromBool(num);

    throw new TypeError('Non-numeric object passed to BN.');
  }

  /*
   * Static Methods
   */

  static min(...args) {
    let min = null;

    for (const num of args) {
      enforce(BN.isBN(num), 'num', 'bignum');

      if (!min || num.cmp(min) < 0)
        min = num;
    }

    return min || new BN(0);
  }

  static max(...args) {
    let max = null;

    for (const num of args) {
      enforce(BN.isBN(num), 'num', 'bignum');

      if (!max || num.cmp(max) > 0)
        max = num;
    }

    return max || new BN(0);
  }

  static cmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.cmp(b);
  }

  static ucmp(a, b) {
    enforce(BN.isBN(a), 'a', 'bignum');
    return a.ucmp(b);
  }

  static red(num) {
    return new Red(num);
  }

  static barrett(num) {
    return new Barrett(num);
  }

  static mont(num) {
    return new Mont(num);
  }

  static _prime(name) {
    if (primes[name])
      return primes[name];

    let prime;

    if (name === 'p192')
      prime = new P192();
    else if (name === 'p224')
      prime = new P224();
    else if (name === 'p521')
      prime = new P521();
    else if (name === 'k256')
      prime = new K256();
    else if (name === 'p251')
      prime = new P251();
    else if (name === 'p25519')
      prime = new P25519();
    else if (name === 'p448')
      prime = new P448();
    else
      throw new Error(`Unknown prime: "${name}".`);

    primes[name] = prime;

    return prime;
  }

  static prime(name) {
    return BN._prime(name).p.clone();
  }

  static pow(num, exp) {
    if (num === 2)
      return BN.shift(1, exp);

    return new BN().fromNumber(num).pown(exp);
  }

  static shift(num, bits) {
    if (num === 1)
      return new BN(0).usetn(bits, 1);

    return new BN().fromNumber(num).ishln(bits);
  }

  static mask(bits) {
    return BN.shift(1, bits).isubn(1);
  }

  static randomBits(rng, bits) {
    enforce(rng != null, 'rng', 'rng');
    enforce((bits >>> 0) === bits, 'bits', 'uint32');

    if (typeof rng === 'object') {
      enforce(typeof rng.randomBytes === 'function', 'rng', 'rng');

      const size = (bits + 7) >>> 3;
      const total = size * 8;
      const bytes = rng.randomBytes(size);

      enforce(Buffer.isBuffer(bytes), 'bytes', 'buffer');

      if (bytes.length !== size)
        throw new RangeError('Invalid number of bytes returned from RNG.');

      const num = BN.fromBuffer(bytes);

      if (total > bits)
        num.iushrn(total - bits);

      return num;
    }

    enforce(typeof rng === 'function', 'rng', 'rng');

    const num = rng(bits);

    enforce(BN.isBN(num), 'num', 'bignum');
    range(num.negative === 0, 'RNG');
    nonred(!num.red, 'RNG');

    if (num.bitLength() > bits)
      throw new RangeError('Invalid number of bits returned from RNG.');

    return num;
  }

  static random(rng, min, max) {
    min = BN.cast(min, 16);
    max = BN.cast(max, 16);

    if (min.cmp(max) > 0)
      throw new RangeError('Minimum cannot be greater than maximum.');

    const space = max.sub(min).iabs();
    const bits = space.bitLength();

    if (bits === 0)
      return min.clone();

    for (;;) {
      const num = BN.randomBits(rng, bits);

      // Maximum is _exclusive_!
      if (num.cmp(space) >= 0)
        continue;

      // Minimum is _inclusive_!
      num.iadd(min);

      return num;
    }
  }

  static of(num, endian) {
    return new BN().of(num, endian);
  }

  static fromNumber(num, endian) {
    return new BN().fromNumber(num, endian);
  }

  static fromDouble(num, endian) {
    return new BN().fromDouble(num, endian);
  }

  static fromBigInt(num, endian) {
    return new BN().fromBigInt(num, endian);
  }

  static fromBool(value) {
    return new BN().fromBool(value);
  }

  static fromString(str, base, endian) {
    return new BN().fromString(str, base, endian);
  }

  static fromJSON(json) {
    return new BN().fromJSON(json);
  }

  static fromBN(num) {
    return new BN().fromBN(num);
  }

  static fromArray(data, endian) {
    return new BN().fromArray(data, endian);
  }

  static fromBuffer(data, endian) {
    return new BN().fromBuffer(data, endian);
  }

  static fromArrayLike(data, endian) {
    return new BN().fromArrayLike(data, endian);
  }

  static decode(data, endian) {
    return new BN().decode(data, endian);
  }

  static from(num, base, endian) {
    return new BN().from(num, base, endian);
  }

  static cast(num, base, endian) {
    if (BN.isBN(num))
      return num;

    return new BN(num, base, endian);
  }

  static isBN(obj) {
    return obj instanceof BN;
  }
}

/*
 * Static
 */

BN.BN = BN;
BN.wordSize = 26;
BN.native = 0;

/**
 * Prime
 */

class Prime {
  constructor(name, p) {
    // P = 2^N - K
    this.name = name;
    this.p = new BN(p, 16);
    this.n = this.p.bitLength();
    this.k = BN.shift(1, this.n).isub(this.p);
    this.lo = this.p.clone();
    this.one = this.p.clone();
  }

  ireduce(num) {
    // Assumes that `num` is less than `P^2`:
    // num = HI * (2^N - K) + HI * K + LO = HI * K + LO (mod P)
    const neg = num.negative !== 0;

    // Track bits.
    let bits = num.bitLength();

    // Must be less than P^2.
    assert(bits <= this.n * 2);

    // Ensure positive.
    num.negative = 0;

    // Reduce.
    while (bits > this.n) {
      // lo = num & ((1 << n) - 1)
      // num = num >> n
      this.split(num, this.lo);

      // num = num * K
      this.imulK(num);

      // num = num + lo
      num._iadd(num, this.lo);

      // bits = bitlen(num)
      bits = num.bitLength();
    }

    // Final reduction.
    const cmp = bits < this.n ? -1 : num.ucmp(this.p);

    if (cmp === 0) {
      num.words[0] = 0;
      num.length = 1;
    } else if (cmp > 0) {
      num._isub(num, this.p);
    } else {
      // Note: we shouldn't need to strip here.
    }

    // Adjust sign.
    if (neg && !num.isZero())
      num._isub(this.p, num);

    return num;
  }

  split(input, out) {
    input._split(this.n, out);
  }

  imulK(num) {
    return num.imul(this.k);
  }

  pm2(x1) {
    // Exponent: p - 2
    throw new Error('Not implemented.');
  }

  fermat(x) {
    return this.pm2(x);
  }
}

/**
 * Prime (3 mod 4)
 */

class Prime34 extends Prime {
  constructor(name, p) {
    super(name, p);
  }

  pm3d4(x1) {
    // Exponent: (p - 3) / 4
    throw new Error('Not implemented.');
  }

  pp1d4(x1) {
    // Exponent: (p + 1) / 4
    throw new Error('Not implemented.');
  }

  sqrt(x) {
    // r = x^((p + 1) / 4) mod p
    const {red} = x;
    const r = this.pp1d4(x);

    if (!red.sqr(r).eq(x))
      throw new SquareRootError(r);

    return r;
  }

  divsqrt(u, v) {
    // x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p
    const {red} = u;
    const u2 = red.sqr(u);
    const u3 = red.mul(u2, u);
    const u5 = red.mul(u3, u2);
    const v3 = red.mul(red.sqr(v), v);
    const p = this.pm3d4(red.mul(u5, v3));
    const x = red.mul(red.mul(u3, v), p);
    const c = red.mul(v, red.sqr(x));

    if (c.eq(u))
      return x;

    throw new SquareRootError(x);
  }
}

/**
 * Prime (5 mod 8)
 */

class Prime58 extends Prime {
  constructor(name, p, sm1) {
    super(name, p);

    this.sm1 = new BN(sm1, 16);
  }

  pm5d8(x1) {
    // Exponent: (p - 5) / 8
    throw new Error('Not implemented.');
  }

  pp3d8(x1) {
    // Exponent: (p + 3) / 8
    throw new Error('Not implemented.');
  }

  sqrt(x) {
    // r = x^((p + 3) / 8) mod p
    const {red} = x;
    const sm1 = this.sm1._forceRed(red);
    const r = this.pp3d8(x);

    if (red.sqr(r).eq(x))
      return r;

    const c = red.mul(r, sm1);

    if (red.sqr(c).eq(x))
      return c;

    throw new SquareRootError(r);
  }

  divsqrt(u, v) {
    // x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
    const {red} = u;
    const sm1 = this.sm1._forceRed(red);
    const v3 = red.mul(red.sqr(v), v);
    const v7 = red.mul(red.sqr(v3), v);
    const p = this.pm5d8(red.mul(u, v7));
    const x = red.mul(red.mul(u, v3), p);
    const c = red.mul(v, red.sqr(x));

    if (c.eq(u))
      return x;

    const mc = red.ineg(c);

    if (mc.eq(u))
      return red.mul(x, sm1);

    if (mc.eq(red.mul(u, sm1)))
      throw new SquareRootError(red.mul(x, sm1));

    throw new SquareRootError(x);
  }
}

/**
 * Prime (1 mod 16)
 */

class Prime116 extends Prime {
  constructor(name, p, g) {
    super(name, p);

    this.g = new BN(g, 16);
    this.z = this.p.subn(1).zeroBits();
  }

  powS(x1) {
    // Exponent: (p - 1) / 2^k
    throw new Error('Not implemented.');
  }

  powE(x1) {
    // Exponent: (s + 1) / 2
    throw new Error('Not implemented.');
  }

  sqrt(x) {
    // Tonelli-Shanks (variable time).
    //
    // Constants:
    //
    //   k = factors of 2 for (p - 1)
    //   s = (p - 1) / 2^k
    //   e = (s + 1) / 2
    //   n = first non-square in F(p)
    //
    // Algorithm:
    //
    //   g = n^s mod p
    //   y = x^e mod p
    //   b = x^s mod p
    //
    //   loop:
    //     t = b
    //     m = 0
    //
    //     while t != 1:
    //       t = t^2 mod p
    //       m += 1
    //
    //     if m == 0:
    //       break
    //
    //     if m >= k:
    //       fail
    //
    //     t = g^(2^(k - m - 1)) mod p
    //     g = t^2 mod p
    //     y = y * t mod p
    //     b = b * g mod p
    //     k = m
    //
    //   return y
    //
    const {red} = x;

    switch (red.jacobi(x)) {
      case -1:
        throw new SquareRootError(x);
      case 0:
        return x.clone();
      case 1:
        break;
    }

    let g = this.g._forceRed(red);
    let y = this.powE(x);
    let b = this.powS(x);
    let k = this.z;

    for (;;) {
      let t = b;
      let m = 0;

      while (t.cmpn(1) !== 0 && m < k) {
        t = red.sqr(t);
        m += 1;
      }

      if (m === 0)
        break;

      assert(m < k);

      t = red.sqrn(g, k - m - 1);
      g = red.sqr(t);
      y = red.mul(y, t);
      b = red.mul(b, g);
      k = m;
    }

    return y;
  }

  divsqrt(u, v) {
    const {red} = u;

    if (v.isZero())
      throw new SquareRootError(v);

    return this.sqrt(red.div(u, v));
  }
}

/**
 * P192
 */

class P192 extends Prime34 {
  constructor() {
    // 2^192 - 2^64 - 1 (= 3 mod 4)
    super('p192', 'ffffffff ffffffff ffffffff fffffffe'
                + 'ffffffff ffffffff');
  }

  imulK(num) {
    // K = 0x10000000000000001
    // K = 2^64 + 1
    const one = this.one.inject(num);
    return num.iushln(64)._iadd(num, one);
  }

  core(x1) {
    // Exponent: (p - 3) / 4
    // Bits: 127x1 1x0 62x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x3 = red.sqrnmul(x2, 1, x1);
    const x6 = red.sqrnmul(x3, 3, x3);
    const x12 = red.sqrnmul(x6, 6, x6);
    const x24 = red.sqrnmul(x12, 12, x12);
    const x30 = red.sqrnmul(x24, 6, x6);
    const x31 = red.sqrnmul(x30, 1, x1);
    const x62 = red.sqrnmul(x31, 31, x31);
    const x124 = red.sqrnmul(x62, 62, x62);
    const x127 = red.sqrnmul(x124, 3, x3);
    const r0 = red.sqrn(x127, 1);
    const r1 = red.sqrnmul(r0, 62, x62);

    return r1;
  }

  pm3d4(x1) {
    // Exponent: (p - 3) / 4
    // Bits: 127x1 1x0 62x1
    return this.core(x1);
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 127x1 1x0 62x1 1x0 1x1
    const {red} = x1;
    const r0 = this.core(x1);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);

    return r2;
  }

  pp1d4(x1) {
    // Exponent: (p + 1) / 4
    // Bits: 128x1 62x0
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x4 = red.sqrnmul(x2, 2, x2);
    const x8 = red.sqrnmul(x4, 4, x4);
    const x16 = red.sqrnmul(x8, 8, x8);
    const x32 = red.sqrnmul(x16, 16, x16);
    const x64 = red.sqrnmul(x32, 32, x32);
    const x128 = red.sqrnmul(x64, 64, x64);
    const r0 = red.sqrn(x128, 62);

    return r0;
  }
}

/**
 * P224
 */

class P224 extends Prime116 {
  constructor() {
    // 2^224 - 2^96 + 1 (1 mod 16)
    super('p224', 'ffffffff ffffffff ffffffff ffffffff'
                + '00000000 00000000 00000001',
                  '6a0fec67 8598a792 0c55b2d4 0b2d6ffb'
                + 'bea3d8ce f3fb3632 dc691b74');
  }

  imulK(num) {
    // K = 0xffffffffffffffffffffffff
    // K = 2^96 - 1
    const one = this.one.inject(num);
    return num.iushln(96)._isub(num, one);
  }

  powS(x1) {
    // Exponent: 2^128 - 1
    // Bits: 128x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x4 = red.sqrnmul(x2, 2, x2);
    const x8 = red.sqrnmul(x4, 4, x4);
    const x16 = red.sqrnmul(x8, 8, x8);
    const x32 = red.sqrnmul(x16, 16, x16);
    const x64 = red.sqrnmul(x32, 32, x32);
    const x128 = red.sqrnmul(x64, 64, x64);

    return x128;
  }

  powE(x1) {
    // Exponent: 2^127
    // Bits: 1x1 127x0
    const {red} = x1;
    const r0 = red.sqrn(x1, 127);

    return r0;
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 127x1 1x0 96x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x3 = red.sqrnmul(x2, 1, x1);
    const x6 = red.sqrnmul(x3, 3, x3);
    const x12 = red.sqrnmul(x6, 6, x6);
    const x24 = red.sqrnmul(x12, 12, x12);
    const x48 = red.sqrnmul(x24, 24, x24);
    const x96 = red.sqrnmul(x48, 48, x48);
    const x120 = red.sqrnmul(x96, 24, x24);
    const x126 = red.sqrnmul(x120, 6, x6);
    const x127 = red.sqrnmul(x126, 1, x1);
    const r0 = red.sqrn(x127, 1);
    const r1 = red.sqrnmul(r0, 96, x96);

    return r1;
  }
}

/**
 * P521
 */

class P521 extends Prime34 {
  constructor() {
    // 2^521 - 1 (= 3 mod 4)
    super('p521', '000001ff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff');
  }

  imulK(num) {
    // K = 0x01
    return num;
  }

  core(x1) {
    // Exponent: 2^519 - 1
    // Bits: 519x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x3 = red.sqrnmul(x2, 1, x1);
    const x6 = red.sqrnmul(x3, 3, x3);
    const x7 = red.sqrnmul(x6, 1, x1);
    const x8 = red.sqrnmul(x7, 1, x1);
    const x16 = red.sqrnmul(x8, 8, x8);
    const x32 = red.sqrnmul(x16, 16, x16);
    const x64 = red.sqrnmul(x32, 32, x32);
    const x128 = red.sqrnmul(x64, 64, x64);
    const x256 = red.sqrnmul(x128, 128, x128);
    const x512 = red.sqrnmul(x256, 256, x256);
    const x519 = red.sqrnmul(x512, 7, x7);

    return x519;
  }

  pm3d4(x1) {
    // Exponent: 2^519 - 1
    // Bits: 519x1
    return this.core(x1);
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 519x1 1x0 1x1
    const {red} = x1;
    const r0 = this.core(x1);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);

    return r2;
  }

  pp1d4(x1) {
    // Exponent: (p + 1) / 4
    // Bits: 1x1 519x0
    const {red} = x1;
    const r0 = red.sqrn(x1, 519);

    return r0;
  }
}

/**
 * K256
 */

class K256 extends Prime34 {
  constructor() {
    // 2^256 - 2^32 - 977 (= 3 mod 4)
    super('k256', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe fffffc2f');
  }

  split(input, output) {
    // 256 = 9 * 26 + 22
    const mask = 0x3fffff;
    const len = Math.min(input.length, 9);

    output._alloc(len + 1);

    for (let i = 0; i < len; i++)
      output.words[i] = input.words[i];

    output.length = len;

    if (input.length <= 9) {
      output._strip();
      input.words[0] = 0;
      input.length = 1;
      return;
    }

    // Shift by 9 limbs.
    let prev = input.words[9];
    let i = 10;

    output.words[output.length++] = prev & mask;
    output._strip();

    for (; i < input.length; i++) {
      const next = input.words[i] | 0;

      input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);

      prev = next;
    }

    prev >>>= 22;

    input.words[i - 10] = prev;

    if (prev === 0 && input.length > 10)
      input.length -= 10;
    else
      input.length -= 9;

    input._strip(); // Unsure if we need this.
  }

  imulK(num) {
    // K = 0x1000003d1 = [0x40, 0x3d1]
    // K = 2^32 + 977
    num._expand(num.length + 2);

    // Bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
    let lo = 0;

    for (let i = 0; i < num.length; i++) {
      const w = num.words[i];

      lo += w * 0x3d1;

      num.words[i] = lo & 0x3ffffff;

      lo = w * 0x40 + Math.floor(lo / 0x4000000);
    }

    // Fast length reduction.
    if (num.words[num.length - 1] === 0) {
      num.length -= 1;
      if (num.words[num.length - 1] === 0)
        num.length -= 1;
    }

    // Note: we shouldn't need to strip here.
    return num;
  }

  core(x1, x2) {
    // Exponent: (p - 47) / 64
    // Bits: 223x1 1x0 22x1 4x0
    const {red} = x1;
    const x3 = red.sqrnmul(x2, 1, x1);
    const x6 = red.sqrnmul(x3, 3, x3);
    const x9 = red.sqrnmul(x6, 3, x3);
    const x11 = red.sqrnmul(x9, 2, x2);
    const x22 = red.sqrnmul(x11, 11, x11);
    const x44 = red.sqrnmul(x22, 22, x22);
    const x88 = red.sqrnmul(x44, 44, x44);
    const x176 = red.sqrnmul(x88, 88, x88);
    const x220 = red.sqrnmul(x176, 44, x44);
    const x223 = red.sqrnmul(x220, 3, x3);
    const r0 = red.sqrn(x223, 1);
    const r1 = red.sqrnmul(r0, 22, x22);
    const r2 = red.sqrn(r1, 4);

    return r2;
  }

  pm3d4(x1) {
    // Exponent: (p - 3) / 4
    // Bits: 223x1 1x0 22x1 4x0 1x1 1x0 2x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r2 = this.core(x1, x2);
    const r3 = red.sqrnmul(r2, 1, x1);
    const r4 = red.sqrn(r3, 1);
    const r5 = red.sqrnmul(r4, 2, x2);

    return r5;
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 223x1 1x0 22x1 4x0 1x1 1x0 2x1 1x0 1x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r2 = this.core(x1, x2);
    const r3 = red.sqrnmul(r2, 1, x1);
    const r4 = red.sqrn(r3, 1);
    const r5 = red.sqrnmul(r4, 2, x2);
    const r6 = red.sqrn(r5, 1);
    const r7 = red.sqrnmul(r6, 1, x1);

    return r7;
  }

  pp1d4(x1) {
    // Exponent: (p + 1) / 4
    // Bits: 223x1 1x0 22x1 4x0 2x1 2x0
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r2 = this.core(x1, x2);
    const r3 = red.sqrnmul(r2, 2, x2);
    const r4 = red.sqrn(r3, 2);

    return r4;
  }
}

/**
 * P251
 */

class P251 extends Prime34 {
  constructor() {
    // 2^251 - 9
    super('p251', '07ffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff ffffffff fffffff7');
  }

  imulK(num) {
    // K = 0x09
    if (num.isZero())
      return num;

    let carry = 0;

    for (let i = 0; i < num.length; i++) {
      const w = num.words[i] * 0x09 + carry;

      carry = w >>> 26;

      num.words[i] = w & 0x3ffffff;
    }

    if (carry !== 0) {
      num._alloc(num.length + 1);
      num.words[num.length++] = carry;
    }

    // Note: we shouldn't need to strip here.
    return num;
  }

  core(x1) {
    // Exponent: 2^247 - 1
    // Bits: 247x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x3 = red.sqrnmul(x2, 1, x1);
    const x6 = red.sqrnmul(x3, 3, x3);
    const x12 = red.sqrnmul(x6, 6, x6);
    const x24 = red.sqrnmul(x12, 12, x12);
    const x48 = red.sqrnmul(x24, 24, x24);
    const x96 = red.sqrnmul(x48, 48, x48);
    const x192 = red.sqrnmul(x96, 96, x96);
    const x240 = red.sqrnmul(x192, 48, x48);
    const x246 = red.sqrnmul(x240, 6, x6);
    const x247 = red.sqrnmul(x246, 1, x1);

    return x247;
  }

  pm3d4(x1) {
    // Exponent: (p - 3) / 4
    // Bits: 247x1 1x0 1x1
    const {red} = x1;
    const r0 = this.core(x1);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);

    return r2;
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 247x1 1x0 1x1 1x0 1x1
    const {red} = x1;
    const r0 = this.core(x1);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);
    const r3 = red.sqrn(r2, 1);
    const r4 = red.sqrnmul(r3, 1, x1);

    return r4;
  }

  pp1d4(x1) {
    // Exponent: (p + 1) / 4
    // Bits: 248x1 1x0
    const {red} = x1;
    const r0 = this.core(x1);
    const r1 = red.sqrnmul(r0, 1, x1);
    const r2 = red.sqrn(r1, 1);

    return r2;
  }
}

/**
 * P25519
 */

class P25519 extends Prime58 {
  constructor() {
    // 2^255 - 19 (= 5 mod 8)
    super('p25519', '7fffffff ffffffff ffffffff ffffffff'
                  + 'ffffffff ffffffff ffffffff ffffffed',
                    '2b832480 4fc1df0b 2b4d0099 3dfbd7a7'
                  + '2f431806 ad2fe478 c4ee1b27 4a0ea0b0');
  }

  imulK(num) {
    // K = 0x13
    let carry = 0;

    for (let i = 0; i < num.length; i++) {
      const w = num.words[i] * 0x13 + carry;

      carry = w >>> 26;

      num.words[i] = w & 0x3ffffff;
    }

    if (carry !== 0) {
      num._alloc(num.length + 1);
      num.words[num.length++] = carry;
    }

    // Note: we shouldn't need to strip here.
    return num;
  }

  core(x1, x2) {
    // Exponent: 2^250 - 1
    // Bits: 250x1
    const {red} = x1;
    const x4 = red.sqrnmul(x2, 2, x2);
    const x5 = red.sqrnmul(x4, 1, x1);
    const x10 = red.sqrnmul(x5, 5, x5);
    const x20 = red.sqrnmul(x10, 10, x10);
    const x40 = red.sqrnmul(x20, 20, x20);
    const x50 = red.sqrnmul(x40, 10, x10);
    const x100 = red.sqrnmul(x50, 50, x50);
    const x200 = red.sqrnmul(x100, 100, x100);
    const x250 = red.sqrnmul(x200, 50, x50);

    return x250;
  }

  pm5d8(x1) {
    // Exponent: (p - 5) / 8
    // Bits: 250x1 1x0 1x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r0 = this.core(x1, x2);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);

    return r2;
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 250x1 1x0 1x1 1x0 2x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r0 = this.core(x1, x2);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);
    const r3 = red.sqrn(r2, 1);
    const r4 = red.sqrnmul(r3, 2, x2);

    return r4;
  }

  pp3d8(x1) {
    // Exponent: (p + 3) / 8
    // Bits: 251x1 1x0
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r0 = this.core(x1, x2);
    const r1 = red.sqrnmul(r0, 1, x1);
    const r2 = red.sqrn(r1, 1);

    return r2;
  }
}

/**
 * P448
 */

class P448 extends Prime34 {
  constructor() {
    // 2^448 - 2^224 - 1 (= 3 mod 4)
    super('p448', 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff fffffffe ffffffff'
                + 'ffffffff ffffffff ffffffff ffffffff'
                + 'ffffffff ffffffff');
  }

  imulK(num) {
    // K = 0x100000000000000000000000000000000000000000000000000000001
    // K = 2^224 + 1
    const one = this.one.inject(num);
    return num.iushln(224)._iadd(num, one);
  }

  core(x1, x2) {
    // Exponent: 2^222 - 1
    // Bits: 222x1
    const {red} = x1;
    const x3 = red.sqrnmul(x2, 1, x1);
    const x6 = red.sqrnmul(x3, 3, x3);
    const x9 = red.sqrnmul(x6, 3, x3);
    const x11 = red.sqrnmul(x9, 2, x2);
    const x22 = red.sqrnmul(x11, 11, x11);
    const x44 = red.sqrnmul(x22, 22, x22);
    const x88 = red.sqrnmul(x44, 44, x44);
    const x176 = red.sqrnmul(x88, 88, x88);
    const x220 = red.sqrnmul(x176, 44, x44);
    const x222 = red.sqrnmul(x220, 2, x2);

    return x222;
  }

  pm3d4(x1) {
    // Exponent: (p - 3) / 4
    // Bits: 223x1 1x0 222x1
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const x222 = this.core(x1, x2);
    const r0 = red.sqrnmul(x222, 1, x1);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 222, x222);

    return r2;
  }

  pm2(x1) {
    // Exponent: p - 2
    // Bits: 223x1 1x0 222x1 1x0 1x1
    const {red} = x1;
    const r0 = this.pm3d4(x1);
    const r1 = red.sqrn(r0, 1);
    const r2 = red.sqrnmul(r1, 1, x1);

    return r2;
  }

  pp1d4(x1) {
    // Exponent: (p + 1) / 4
    // Bits: 224x1 222x0
    const {red} = x1;
    const x2 = red.sqrnmul(x1, 1, x1);
    const r0 = this.core(x1, x2);
    const r1 = red.sqrnmul(r0, 2, x2);
    const r2 = red.sqrn(r1, 222);

    return r2;
  }
}

/**
 * Reduction Engine
 */

class Red {
  constructor(m) {
    let prime = null;

    if (typeof m === 'string') {
      prime = BN._prime(m);
      m = prime.p;
    }

    enforce(BN.isBN(m), 'm', 'bignum');
    nonred(!m.red, 'reduction');
    range(m.sign() > 0, 'reduction');

    this.m = m;
    this.prime = prime;
    this.mb = null;
    this.sm1 = null;
  }

  _verify1(a) {
    range(a.negative === 0, 'red');
    red(a.red != null, 'red');
  }

  _verify2(a, b) {
    range((a.negative | b.negative) === 0, 'red');
    red(a.red != null && a.red === b.red, 'red');
  }

  get mont() {
    return false;
  }

  precompute() {
    // Precompute `sqrt(-1)` for primes congruent to 5 mod 8.
    if (this.sm1 === null && this.m.andln(7) === 5) {
      if (this.prime) {
        this.sm1 = this.prime.sm1.clone()._forceRed(this);
      } else {
        const x = new BN(2).toRed(this);
        const e = this.m.subn(1).iushrn(2);

        // sqrt(-1) = 2^((p - 1) / 4) mod p
        this.sm1 = this.pow(x, e);
      }
    }

    return this;
  }

  convertTo(num) {
    const res = num.mod(this.m);
    res.red = this;
    return res;
  }

  convertFrom(num) {
    const res = num.clone();
    res.red = null;
    return res;
  }

  intTo(a) {
    return a;
  }

  intFrom(a) {
    return a;
  }

  imod(a) {
    if (this.prime)
      return this.prime.ireduce(a)._forceRed(this);

    return a.imod(this.m)._forceRed(this);
  }

  iadd(a, b) {
    this._verify2(a, b);

    a._iadd(a, b);

    if (a.ucmp(this.m) >= 0)
      a._isub(a, this.m);

    return a;
  }

  add(a, b) {
    if (a.length < b.length)
      return this.iadd(b.clone(), a);

    return this.iadd(a.clone(), b);
  }

  iaddn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.isubn(a, -num);

    if (this.m.length === 1)
      num %= this.m.words[0];

    a._iaddn(num);

    if (a.ucmp(this.m) >= 0)
      a._isub(a, this.m);

    return a;
  }

  addn(a, num) {
    return this.iaddn(a.clone(), num);
  }

  isub(a, b) {
    this._verify2(a, b);

    //  0: a - a mod m == 0
    // -1: a - b mod m == m - (b - a)
    // +1: a - b mod m == a - b
    const cmp = a.ucmp(b);

    if (cmp === 0) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    if (cmp < 0) {
      a._isub(b, a);
      a._isub(this.m, a);
    } else {
      a._isub(a, b);
    }

    return a;
  }

  sub(a, b) {
    return this.isub(a.clone(), b);
  }

  isubn(a, num) {
    this._verify1(a);

    if (num < 0)
      return this.iaddn(a, -num);

    if (this.m.length === 1)
      num %= this.m.words[0];

    //  <: a - b mod m == m - (b - a)
    // >=: a - b mod m == a - b
    if (a.length === 1 && a.words[0] < num) {
      a.words[0] = num - a.words[0];
      a._isub(this.m, a);
    } else {
      a._isubn(num);
    }

    return a;
  }

  subn(a, num) {
    return this.isubn(a.clone(), num);
  }

  imul(a, b) {
    this._verify2(a, b);
    return this.imod(a.imul(b));
  }

  mul(a, b) {
    this._verify2(a, b);
    return this.imod(a.mul(b));
  }

  imuln(a, num) {
    this._verify1(a);

    if (a.isZero())
      return a;

    if (num === 0) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    const neg = num < 0;

    if (neg)
      num = -num;

    if (this.m.length === 1)
      num %= this.m.words[0];

    a.imuln(num);

    if (num <= 16) {
      // Quick reduction.
      while (a.ucmp(this.m) >= 0)
        a._isub(a, this.m);
    } else {
      this.imod(a);
    }

    if (neg)
      this.ineg(a);

    return a;
  }

  muln(a, num) {
    return this.imuln(a.clone(), num);
  }

  idiv(a, b) {
    return this.div(a, b)._move(a);
  }

  div(a, b) {
    return this.mul(a, this.invert(b));
  }

  idivn(a, num) {
    return this.divn(a, num)._move(a);
  }

  divn(a, num) {
    return this.div(a, this.convertTo(new BN(num)));
  }

  ipow(a, num) {
    return this.pow(a, num)._move(a);
  }

  pow(a, num) {
    this._verify1(a);

    if (num.isNeg())
      a = this.invert(a);

    // Small exponent.
    if (num.length === 1)
      return this.pown(a, num.words[0]);

    // Call out to BigInt.
    if (HAS_BIGINT && !this.prime)
      return this.powInt(a, num);

    // Otherwise, a BN implementation.
    return this.powNum(a, num);
  }

  powNum(a, num) {
    // Sliding window (odd multiples only).
    const one = new BN(1).toRed(this);
    const wnd = new Array(WND_SIZE);
    const a2 = this.sqr(a);

    wnd[0] = a;

    for (let i = 1; i < WND_SIZE; i++)
      wnd[i] = this.mul(wnd[i - 1], a2);

    let i = num.bitLength();
    let r = one;

    while (i >= WND_WIDTH) {
      let width = WND_WIDTH;
      let bits = num.bits(i - width, width);

      if (bits < WND_SIZE) {
        r = this.sqr(r);
        i -= 1;
        continue;
      }

      while ((bits & 1) === 0) {
        width -= 1;
        bits >>= 1;
      }

      if (r === one) {
        r = wnd[bits >> 1].clone();
      } else {
        r = this.sqrn(r, width);
        r = this.mul(r, wnd[bits >> 1]);
      }

      i -= width;
    }

    if (i > 0) {
      const bits = num.bits(0, i);

      while (i--) {
        r = this.sqr(r);

        if ((bits >> i) & 1)
          r = this.mul(r, a);
      }
    }

    return r;
  }

  powInt(a, num) {
    if (this.mb === null)
      this.mb = this.m.toBigInt();

    const x = this.intFrom(a.toBigInt());
    const y = powInt(x, num, this.mb);
    const z = this.intTo(y);

    return BN.fromBigInt(z)._forceRed(this);
  }

  sqrn(a, n) {
    while (n--)
      a = this.sqr(a);

    return a;
  }

  sqrnmul(a, n, b) {
    return this.mul(this.sqrn(a, n), b);
  }

  ipown(a, num) {
    return this.pown(a, num)._move(a);
  }

  pown(a, num) {
    this._verify1(a);

    if (num < 0) {
      a = this.invert(a);
      num = -num;
    }

    if (num === 0)
      return new BN(1).toRed(this);

    if (num === 1)
      return a.clone();

    const bits = countBits(num);

    let r = a;

    for (let i = bits - 2; i >= 0; i--) {
      r = this.sqr(r);

      if ((num >> i) & 1)
        r = this.mul(r, a);
    }

    return r;
  }

  isqr(a) {
    return this.imul(a, a);
  }

  sqr(a) {
    return this.mul(a, a);
  }

  isqrt(x) {
    return this.sqrt(x)._move(x);
  }

  sqrt(x) {
    this._verify1(x);

    // Optimized square root chain.
    if (this.prime)
      return this.prime.sqrt(x);

    // Fast case (p = 3 mod 4).
    if (this.m.andln(3) === 3)
      return this.sqrt3mod4(x);

    // Fast case (p = 5 mod 8).
    if (this.m.andln(7) === 5) {
      if (this.sm1 != null)
        return this.sqrt5mod8sm1(x);
      return this.sqrt5mod8(x);
    }

    // Slow case (Tonelli-Shanks).
    return this.sqrt0(x);
  }

  sqrt3mod4(x) {
    const e = this.m.addn(1).iushrn(2); // (p + 1) / 4
    const b = this.pow(x, e);

    if (!this.sqr(b).eq(x))
      throw new SquareRootError(b);

    return b;
  }

  sqrt5mod8(x) {
    // Atkin's Algorithm.
    const one = new BN(1).toRed(this);
    const e = this.m.ushrn(3); // (p - 5) / 8
    const x2 = this.add(x, x);
    const alpha = this.pow(x2, e);
    const beta = this.mul(x2, this.sqr(alpha));
    const b = this.mul(this.mul(alpha, x), this.isub(beta, one));

    if (!this.sqr(b).eq(x))
      throw new SquareRootError(b);

    return b;
  }

  sqrt5mod8sm1(x) {
    const e = this.m.addn(3).iushrn(3); // (p + 3) / 8
    const b = this.pow(x, e);

    if (this.sqr(b).eq(x))
      return b;

    const c = this.mul(b, this.sm1);

    if (this.sqr(c).eq(x))
      return c;

    throw new SquareRootError(b);
  }

  sqrt0(x) {
    if (this.m.cmpn(1) === 0 || !this.m.isOdd())
      throw new Error('Invalid prime.');

    switch (this.jacobi(x)) {
      case -1:
        throw new SquareRootError(x);
      case 0:
        return x.clone();
      case 1:
        break;
    }

    const one = new BN(1).toRed(this);
    const s = this.m.subn(1);
    const e = s._makeOdd();
    const n = new BN(2).toRed(this);

    while (this.jacobi(n) !== -1)
      this.iadd(n, one);

    let g = this.pow(n, s);
    let b = this.pow(x, s);
    let y = this.pow(x, s.iaddn(1).iushrn(1));
    let k = e;

    for (;;) {
      let t = b;
      let m = 0;

      while (!t.eq(one) && m < k) {
        t = this.sqr(t);
        m += 1;
      }

      if (m === 0)
        break;

      assert(m < k);

      t = this.sqrn(g, k - m - 1);
      g = this.sqr(t);
      y = this.mul(y, t);
      b = this.mul(b, g);
      k = m;
    }

    return y;
  }

  idivsqrt(u, v) {
    return this.divsqrt(u, v)._move(u);
  }

  divsqrt(u, v) {
    this._verify2(u, v);

    // u = 0, v = 0
    if (u.isZero() && v.isZero())
      throw new SquareRootError(v);

    // Optimized inverse square root chain.
    if (this.prime)
      return this.prime.divsqrt(u, v);

    // p = 3 mod 4
    if (this.m.andln(3) === 3)
      return this.divsqrt3mod4(u, v);

    // p = 5 mod 8
    if (this.sm1 != null && this.m.andln(7) === 5)
      return this.divsqrt5mod8(u, v);

    // v = 0
    if (v.isZero())
      throw new SquareRootError(v);

    return this.sqrt(this.div(u, v));
  }

  divsqrt3mod4(u, v) {
    // x = u^3 * v * (u^5 * v^3)^((p - 3) / 4) mod p
    const e = this.m.subn(3).iushrn(2);
    const u2 = this.sqr(u);
    const u3 = this.mul(u2, u);
    const u5 = this.mul(u3, u2);
    const v3 = this.mul(this.sqr(v), v);
    const p = this.pow(this.mul(u5, v3), e);
    const x = this.mul(this.mul(u3, v), p);
    const c = this.mul(v, this.sqr(x));

    if (c.eq(u))
      return x;

    throw new SquareRootError(x);
  }

  divsqrt5mod8(u, v) {
    // x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
    const e = this.m.subn(5).iushrn(3);
    const v3 = this.mul(this.sqr(v), v);
    const v7 = this.mul(this.sqr(v3), v);
    const p = this.pow(this.mul(u, v7), e);
    const x = this.mul(this.mul(u, v3), p);
    const c = this.mul(v, this.sqr(x));

    if (c.eq(u))
      return x;

    const mc = this.ineg(c);

    if (mc.eq(u))
      return this.mul(x, this.sm1);

    if (mc.eq(this.mul(u, this.sm1)))
      throw new SquareRootError(this.mul(x, this.sm1));

    throw new SquareRootError(x);
  }

  isSquare(a) {
    if (this.m.isOdd())
      return this.jacobi(a) >= 0;

    return this.kronecker(a) >= 0;
  }

  ishl(a, num) {
    this._verify1(a);
    return this.imod(a.iushl(num));
  }

  shl(a, num) {
    return this.ishl(a.clone(), num);
  }

  ishln(a, num) {
    this._verify1(a);

    a.iushln(num);

    if (num <= 4) {
      // Quick reduction.
      while (a.ucmp(this.m) >= 0)
        a._isub(a, this.m);
    } else {
      this.imod(a);
    }

    return a;
  }

  shln(a, num) {
    return this.ishln(a.clone(), num);
  }

  ineg(a) {
    this._verify1(a);

    if (!a.isZero())
      a._isub(this.m, a);

    return a;
  }

  neg(a) {
    return this.ineg(a.clone());
  }

  eq(a, b) {
    this._verify2(a, b);
    return a.ucmp(b) === 0;
  }

  eqn(a, num) {
    this._verify1(a);

    if (this.m.length === 1) {
      num %= this.m.words[0];

      if (num < 0)
        num += this.m.words[0];

      return a.ucmpn(num) === 0;
    }

    if (num < 0) {
      this.m._isubn(-num);

      const cmp = a.ucmp(this.m);

      this.m._iaddn(-num);

      return cmp === 0;
    }

    return a.ucmpn(num) === 0;
  }

  isHigh(a) {
    return !this.isLow(a);
  }

  isLow(a) {
    this._verify1(a);
    return a.ucmp(this.m.ushrn(1)) <= 0;
  }

  isOdd(a) {
    this._verify1(a);
    return a.isOdd();
  }

  isEven(a) {
    this._verify1(a);
    return a.isEven();
  }

  legendre(num) {
    this._verify1(num);

    if (this.m.isEven())
      throw new Error('legendre: `num` must be odd.');

    // Euler's criterion.
    const e = this.m.subn(1).iushrn(1); // (p - 1) / 2
    const symbol = this.pow(num, e);

    if (symbol.isZero())
      return 0;

    const one = new BN(1).toRed(this);

    if (symbol.eq(one))
      return 1;

    if (symbol.eq(this.ineg(one)))
      return -1;

    throw new Error('Invalid prime.');
  }

  jacobi(a) {
    this._verify1(a);
    return a.jacobi(this.m);
  }

  kronecker(a) {
    this._verify1(a);
    return a.kronecker(this.m);
  }

  iinvert(a) {
    return this.invert(a)._move(a);
  }

  invert(a) {
    this._verify1(a);
    return a.invert(this.m)._forceRed(this);
  }

  ifermat(a) {
    return this.fermat(a)._move(a);
  }

  fermat(a) {
    this._verify1(a);

    if (a.isZero() || this.m.cmpn(1) === 0)
      throw new RangeError('Not invertible.');

    // Optimized inversion chain.
    if (this.prime)
      return this.prime.fermat(a);

    // Invert using fermat's little theorem.
    return this.pow(a, this.m.subn(2));
  }

  invertAll(elems) {
    // Montgomery's trick.
    enforce(Array.isArray(elems), 'elems', 'array');

    for (const elem of elems) {
      enforce(BN.isBN(elem), 'elem', 'bignum');

      this._verify1(elem);
    }

    if (this.m.cmpn(1) === 0 || this.m.isEven())
      throw new RangeError('Not invertible.');

    const len = elems.length;
    const invs = new Array(len);

    if (len === 0)
      return invs;

    let acc = new BN(1).toRed(this);

    for (let i = 0; i < len; i++) {
      if (elems[i].isZero()) {
        invs[i] = elems[i].clone();
        continue;
      }

      invs[i] = acc;
      acc = this.mul(acc, elems[i]);
    }

    acc = this.invert(acc);

    for (let i = len - 1; i >= 0; i--) {
      if (elems[i].isZero())
        continue;

      invs[i] = this.mul(acc, invs[i]);
      acc = this.mul(acc, elems[i]);
    }

    return invs;
  }

  [custom]() {
    if (this.prime)
      return `<Red: ${this.prime.name}>`;

    return `<Red: ${this.m.toString(10)}>`;
  }
}

/**
 * Barrett Engine
 */

class Barrett extends Red {
  constructor(m) {
    super(m);

    this.prime = null;
    this.n = this.m.bitLength();

    if ((this.n % 26) !== 0)
      this.n += 26 - (this.n % 26);

    this.k = this.n * 2;
    this.w = this.k / 26;
    this.b = BN.shift(1, this.k).div(this.m);
  }

  convertTo(num) {
    if (num.length > this.w)
      return super.convertTo(num);

    return this.imod(num.clone());
  }

  _shift(q) {
    let i = 0;
    let j = this.w;

    while (j < q.length)
      q.words[i++] = q.words[j++];

    if (i === 0)
      q.words[i++] = 0;

    q.length = i;
  }

  imod(a) {
    const neg = a.negative;

    assert(a.length <= this.w);

    a.negative = 0;

    const q = a.mul(this.b);

    // Shift right by `k` bits.
    this._shift(q);

    a._isub(a, q.mul(this.m));

    if (a.ucmp(this.m) >= 0)
      a._isub(a, this.m);

    if (neg && !a.isZero())
      a._isub(this.m, a);

    a.red = this;

    return a;
  }
}

/**
 * Montgomery Engine
 */

class Mont extends Red {
  constructor(m) {
    super(m);

    // Note that:
    //
    //   mi = (-m^-1 mod (2^(n * 2))) mod r
    //
    // and:
    //
    //   mi = (((2^n)^-1 mod m) * r^-1 - 1) / m
    //
    // are equivalent.
    this.prime = null;
    this.n = this.m.length * 26;
    this.r = BN.shift(1, this.n);
    this.r2 = BN.shift(1, this.n * 2).imod(this.m);
    this.ri = this.r.invert(this.m);
    this.mi = this.r.mul(this.ri).isubn(1).div(this.m);
    this.rib = null;
  }

  get mont() {
    return true;
  }

  convertTo(num) {
    if (num.isNeg() || num.ucmp(this.m) >= 0)
      return this.imod(num.ushln(this.n));

    // Equivalent to: (num * 2^n) mod m
    return this.mul(num, this.r2);
  }

  convertFrom(num) {
    // Equivalent to: num * r^-1 mod m
    const r = this.mul(num, new BN(1));
    r.red = null;
    return r;
  }

  intTo(a) {
    return (a << BigInt(this.n)) % this.mb;
  }

  intFrom(a) {
    if (this.rib === null)
      this.rib = this.ri.toBigInt();

    return (a * this.rib) % this.mb;
  }

  iaddn(a, num) {
    return this.iadd(a, this.convertTo(new BN(num)));
  }

  isubn(a, num) {
    return this.isub(a, this.convertTo(new BN(num)));
  }

  imul(a, b) {
    return this.mul(a, b)._move(a);
  }

  mul(a, b) {
    if (a.isZero() || b.isZero())
      return new BN(0)._forceRed(this);

    const t = a.mul(b);
    const c = t.umaskn(this.n).mul(this.mi).iumaskn(this.n);
    const u = t.iadd(c.mul(this.m)).iushrn(this.n);

    if (u.ucmp(this.m) >= 0)
      u._isub(u, this.m);

    return u._forceRed(this);
  }

  imuln(a, num) {
    this._verify1(a);

    if (a.isZero())
      return a;

    if (num === 0) {
      a.words[0] = 0;
      a.length = 1;
      return a;
    }

    const neg = num < 0;

    if (neg)
      num = -num;

    if (this.m.length === 1)
      num %= this.m.words[0];

    const bits = countBits(num);

    // Potentially compute with additions.
    // This avoids an expensive division.
    if (bits > 5) {
      // Slow case (num > 31).
      this.imul(a, this.convertTo(new BN(num)));
    } else if ((num & (num - 1)) === 0) {
      // Optimize for powers of two.
      for (let i = 0; i < bits - 1; i++)
        this.iadd(a, a);
    } else {
      // Multiply left to right.
      const c = a.clone();

      for (let i = bits - 2; i >= 0; i--) {
        this.iadd(a, a);

        if ((num >> i) & 1)
          this.iadd(a, c);
      }
    }

    if (neg)
      this.ineg(a);

    return a;
  }

  eqn(a, num) {
    this._verify1(a);

    if (num === 0)
      return a.isZero();

    return a.ucmp(this.convertTo(new BN(num))) === 0;
  }

  isLow(a) {
    this._verify1(a);
    return this.convertFrom(a).ucmp(this.m.ushrn(1)) <= 0;
  }

  isOdd(a) {
    this._verify1(a);
    return this.convertFrom(a).isOdd();
  }

  isEven(a) {
    this._verify1(a);
    return this.convertFrom(a).isEven();
  }

  invert(a) {
    this._verify1(a);

    // (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
    return this.imod(a.invert(this.m).mul(this.r2));
  }
}

/*
 * Helpers
 */

function makeError(Error, msg, start) {
  const err = new Error(msg);

  if (Error.captureStackTrace)
    Error.captureStackTrace(err, start);

  return err;
}

function assert(value, message) {
  if (!value) {
    const msg = message || 'Assertion failed.';
    throw makeError(Error, msg, assert);
  }
}

function enforce(value, name, type) {
  if (!value) {
    const msg = `"${name}" must be a(n) ${type}.`;
    throw makeError(TypeError, msg, enforce);
  }
}

function range(value, name) {
  if (!value) {
    const msg = `"${name}" only works with positive numbers.`;
    throw makeError(RangeError, msg, range);
  }
}

function red(value, name) {
  if (!value) {
    const msg = `"${name}" only works with red numbers.`;
    throw makeError(TypeError, msg, red);
  }
}

function nonred(value, name) {
  if (!value) {
    const msg = `"${name}" only works with normal numbers.`;
    throw makeError(TypeError, msg, nonred);
  }
}

function nonzero(value) {
  if (!value) {
    const msg = 'Cannot divide by zero.';
    throw makeError(RangeError, msg, nonzero);
  }
}

class SquareRootError extends Error {
  constructor(result) {
    super();

    this.name = 'SquareRootError';
    this.message = 'X is not a square mod P.';
    this.result = result.fromRed();

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, SquareRootError);
  }
}

function isInteger(num) {
  return Number.isSafeInteger(num);
}

function isSMI(num) {
  return isInteger(num)
      && num >= -0x3ffffff
      && num <= 0x3ffffff;
}

function allocate(ArrayType, size) {
  if (ArrayType.allocUnsafeSlow)
    return ArrayType.allocUnsafeSlow(size);

  return new ArrayType(size);
}

function getBase(base) {
  if (base == null)
    return 10;

  if (typeof base === 'number')
    return base;

  switch (base) {
    case 'bin':
      return 2;
    case 'oct':
      return 8;
    case 'dec':
      return 10;
    case 'hex':
      return 16;
  }

  return 0;
}

/*
 * Internal
 */

function countBits(w) {
  if (Math.clz32)
    return 32 - Math.clz32(w);

  let t = w;
  let r = 0;

  if (t >= 0x1000) {
    r += 13;
    t >>>= 13;
  }

  if (t >= 0x40) {
    r += 7;
    t >>>= 7;
  }

  if (t >= 0x8) {
    r += 4;
    t >>>= 4;
  }

  if (t >= 0x02) {
    r += 2;
    t >>>= 2;
  }

  return r + t;
}

function zeroBits(w) {
  // Shortcut.
  if (w === 0)
    return 26;

  let t = w;
  let r = 0;

  if ((t & 0x1fff) === 0) {
    r += 13;
    t >>>= 13;
  }

  if ((t & 0x7f) === 0) {
    r += 7;
    t >>>= 7;
  }

  if ((t & 0xf) === 0) {
    r += 4;
    t >>>= 4;
  }

  if ((t & 0x3) === 0) {
    r += 2;
    t >>>= 2;
  }

  if ((t & 0x1) === 0)
    r += 1;

  return r;
}

function parseHex(str, start, end) {
  const len = Math.min(str.length, end);

  let r = 0;
  let z = 0;

  for (let i = start; i < len; i++) {
    const c = str.charCodeAt(i) - 48;

    r <<= 4;

    let b;

    if (c >= 49 && c <= 54) {
      // 'a' - 'f'
      b = c - 49 + 0xa;
    } else if (c >= 17 && c <= 22) {
      // 'A' - 'F'
      b = c - 17 + 0xa;
    } else {
      // '0' - '9'
      b = c;
    }

    r |= b;
    z |= b;
  }

  if (z & ~15)
    throw new Error('Invalid string.');

  return r;
}

function parseBase(str, start, end, mul) {
  const len = Math.min(str.length, end);

  let r = 0;

  for (let i = start; i < len; i++) {
    const c = str.charCodeAt(i) - 48;

    r *= mul;

    let b;

    if (c >= 49) {
      // 'a'
      b = c - 49 + 0xa;
    } else if (c >= 17) {
      // 'A'
      b = c - 17 + 0xa;
    } else {
      // '0' - '9'
      b = c;
    }

    if (c < 0 || c > 207 || b >= mul)
      throw new Error('Invalid string.');

    r += b;
  }

  return r;
}

/*
 * Exponentiation (bigint)
 */

function powInt(x, e, m) {
  // Sliding window (odd multiples only).
  const one = BigInt(1);
  const wnd = new Array(WND_SIZE);
  const x2 = (x * x) % m;

  wnd[0] = x;

  for (let i = 1; i < WND_SIZE; i++)
    wnd[i] = (wnd[i - 1] * x2) % m;

  let i = e.bitLength();
  let r = one;

  while (i >= WND_WIDTH) {
    let width = WND_WIDTH;
    let bits = e.bits(i - width, width);

    if (bits < WND_SIZE) {
      r = (r * r) % m;
      i -= 1;
      continue;
    }

    while ((bits & 1) === 0) {
      width -= 1;
      bits >>= 1;
    }

    if (r === one) {
      r = wnd[bits >> 1];
    } else {
      r = sqrn(r, width, m);
      r = (r * wnd[bits >> 1]) % m;
    }

    i -= width;
  }

  if (i > 0) {
    const bits = e.bits(0, i);

    while (i--) {
      r = (r * r) % m;

      if ((bits >> i) & 1)
        r = (r * x) % m;
    }
  }

  return r;
}

function sqrn(x, n, m) {
  for (let i = 0; i < n; i++)
    x = (x * x) % m;
  return x;
}

/*
 * Multiplication
 */

function smallMulTo(self, num, out) {
  const len = self.length + num.length;

  out.negative = self.negative ^ num.negative;
  out._alloc(len);
  out.length = len;

  // Peel one iteration (compiler can't
  // do it, because of code complexity).
  const a = self.words[0];
  const b = num.words[0];
  const r = a * b;
  const lo = r & 0x3ffffff;

  let carry = (r / 0x4000000) | 0;
  let k = 1;

  out.words[0] = lo;

  for (; k < out.length - 1; k++) {
    // Sum all words with the same
    // `i + j = k` and accumulate
    // `ncarry`, note that ncarry
    // could be >= 0x3ffffff.
    let ncarry = carry >>> 26;
    let rword = carry & 0x3ffffff;

    const min = Math.max(0, k - self.length + 1);
    const max = Math.min(k, num.length - 1);

    for (let j = min; j <= max; j++) {
      const i = k - j;
      const a = self.words[i];
      const b = num.words[j];
      const r = a * b + rword;

      ncarry += (r / 0x4000000) | 0;
      rword = r & 0x3ffffff;
    }

    out.words[k] = rword | 0;
    carry = ncarry | 0;
  }

  if (carry !== 0)
    out.words[k] = carry | 0;
  else
    out.length -= 1;

  return out._strip();
}

function bigMulTo(self, num, out) {
  const len = self.length + num.length;

  out.negative = self.negative ^ num.negative;
  out._alloc(len);
  out.length = len;

  let carry = 0;
  let hncarry = 0;
  let k = 0;

  for (; k < out.length - 1; k++) {
    // Sum all words with the same
    // `i + j = k` and accumulate
    // `ncarry`, note that ncarry
    // could be >= 0x3ffffff.
    let ncarry = hncarry;

    hncarry = 0;

    let rword = carry & 0x3ffffff;

    const min = Math.max(0, k - self.length + 1);
    const max = Math.min(k, num.length - 1);

    for (let j = min; j <= max; j++) {
      const i = k - j;
      const a = self.words[i];
      const b = num.words[j];
      const r = a * b;

      let lo = r & 0x3ffffff;

      ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
      lo = (lo + rword) | 0;
      rword = lo & 0x3ffffff;
      ncarry = (ncarry + (lo >>> 26)) | 0;

      hncarry += ncarry >>> 26;
      ncarry &= 0x3ffffff;
    }

    out.words[k] = rword;
    carry = ncarry;
    ncarry = hncarry;
  }

  if (carry !== 0)
    out.words[k] = carry;
  else
    out.length -= 1;

  return out._strip();
}

function jumboMulTo(x, y, out) {
  // v8 has a 2147483519 bit max (~256mb).
  if (!HAS_BIGINT || x.length + y.length > 82595519)
    return bigMulTo(x, y, out);

  const zero = BigInt(0);
  const mask = BigInt(0x3ffffff);
  const shift = BigInt(26);

  let z = x.toBigInt() * y.toBigInt();

  const neg = (z < zero) | 0;

  if (neg)
    z = -z;

  let i = 0;

  while (z > zero) {
    out.words[i++] = Number(z & mask);
    z >>= shift;
  }

  if (i === 0)
    out.words[i++] = 0;

  out.length = i;
  out.negative = neg;

  return out;
}

function comb10MulTo(self, num, out) {
  const a = self.words;
  const b = num.words;
  const o = out.words;
  const a0 = a[0] | 0;
  const al0 = a0 & 0x1fff;
  const ah0 = a0 >>> 13;
  const a1 = a[1] | 0;
  const al1 = a1 & 0x1fff;
  const ah1 = a1 >>> 13;
  const a2 = a[2] | 0;
  const al2 = a2 & 0x1fff;
  const ah2 = a2 >>> 13;
  const a3 = a[3] | 0;
  const al3 = a3 & 0x1fff;
  const ah3 = a3 >>> 13;
  const a4 = a[4] | 0;
  const al4 = a4 & 0x1fff;
  const ah4 = a4 >>> 13;
  const a5 = a[5] | 0;
  const al5 = a5 & 0x1fff;
  const ah5 = a5 >>> 13;
  const a6 = a[6] | 0;
  const al6 = a6 & 0x1fff;
  const ah6 = a6 >>> 13;
  const a7 = a[7] | 0;
  const al7 = a7 & 0x1fff;
  const ah7 = a7 >>> 13;
  const a8 = a[8] | 0;
  const al8 = a8 & 0x1fff;
  const ah8 = a8 >>> 13;
  const a9 = a[9] | 0;
  const al9 = a9 & 0x1fff;
  const ah9 = a9 >>> 13;
  const b0 = b[0] | 0;
  const bl0 = b0 & 0x1fff;
  const bh0 = b0 >>> 13;
  const b1 = b[1] | 0;
  const bl1 = b1 & 0x1fff;
  const bh1 = b1 >>> 13;
  const b2 = b[2] | 0;
  const bl2 = b2 & 0x1fff;
  const bh2 = b2 >>> 13;
  const b3 = b[3] | 0;
  const bl3 = b3 & 0x1fff;
  const bh3 = b3 >>> 13;
  const b4 = b[4] | 0;
  const bl4 = b4 & 0x1fff;
  const bh4 = b4 >>> 13;
  const b5 = b[5] | 0;
  const bl5 = b5 & 0x1fff;
  const bh5 = b5 >>> 13;
  const b6 = b[6] | 0;
  const bl6 = b6 & 0x1fff;
  const bh6 = b6 >>> 13;
  const b7 = b[7] | 0;
  const bl7 = b7 & 0x1fff;
  const bh7 = b7 >>> 13;
  const b8 = b[8] | 0;
  const bl8 = b8 & 0x1fff;
  const bh8 = b8 >>> 13;
  const b9 = b[9] | 0;
  const bl9 = b9 & 0x1fff;
  const bh9 = b9 >>> 13;

  let c = 0;
  let lo, mid, hi;

  out.negative = self.negative ^ num.negative;
  out._alloc(20);
  out.length = 19;

  /* k = 0 */
  lo = Math.imul(al0, bl0);
  mid = Math.imul(al0, bh0);
  mid = (mid + Math.imul(ah0, bl0)) | 0;
  hi = Math.imul(ah0, bh0);

  let w0 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w0 >>> 26)) | 0;
  w0 &= 0x3ffffff;

  /* k = 1 */
  lo = Math.imul(al1, bl0);
  mid = Math.imul(al1, bh0);
  mid = (mid + Math.imul(ah1, bl0)) | 0;
  hi = Math.imul(ah1, bh0);
  lo = (lo + Math.imul(al0, bl1)) | 0;
  mid = (mid + Math.imul(al0, bh1)) | 0;
  mid = (mid + Math.imul(ah0, bl1)) | 0;
  hi = (hi + Math.imul(ah0, bh1)) | 0;

  let w1 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w1 >>> 26)) | 0;
  w1 &= 0x3ffffff;

  /* k = 2 */
  lo = Math.imul(al2, bl0);
  mid = Math.imul(al2, bh0);
  mid = (mid + Math.imul(ah2, bl0)) | 0;
  hi = Math.imul(ah2, bh0);
  lo = (lo + Math.imul(al1, bl1)) | 0;
  mid = (mid + Math.imul(al1, bh1)) | 0;
  mid = (mid + Math.imul(ah1, bl1)) | 0;
  hi = (hi + Math.imul(ah1, bh1)) | 0;
  lo = (lo + Math.imul(al0, bl2)) | 0;
  mid = (mid + Math.imul(al0, bh2)) | 0;
  mid = (mid + Math.imul(ah0, bl2)) | 0;
  hi = (hi + Math.imul(ah0, bh2)) | 0;

  let w2 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w2 >>> 26)) | 0;
  w2 &= 0x3ffffff;

  /* k = 3 */
  lo = Math.imul(al3, bl0);
  mid = Math.imul(al3, bh0);
  mid = (mid + Math.imul(ah3, bl0)) | 0;
  hi = Math.imul(ah3, bh0);
  lo = (lo + Math.imul(al2, bl1)) | 0;
  mid = (mid + Math.imul(al2, bh1)) | 0;
  mid = (mid + Math.imul(ah2, bl1)) | 0;
  hi = (hi + Math.imul(ah2, bh1)) | 0;
  lo = (lo + Math.imul(al1, bl2)) | 0;
  mid = (mid + Math.imul(al1, bh2)) | 0;
  mid = (mid + Math.imul(ah1, bl2)) | 0;
  hi = (hi + Math.imul(ah1, bh2)) | 0;
  lo = (lo + Math.imul(al0, bl3)) | 0;
  mid = (mid + Math.imul(al0, bh3)) | 0;
  mid = (mid + Math.imul(ah0, bl3)) | 0;
  hi = (hi + Math.imul(ah0, bh3)) | 0;

  let w3 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w3 >>> 26)) | 0;
  w3 &= 0x3ffffff;

  /* k = 4 */
  lo = Math.imul(al4, bl0);
  mid = Math.imul(al4, bh0);
  mid = (mid + Math.imul(ah4, bl0)) | 0;
  hi = Math.imul(ah4, bh0);
  lo = (lo + Math.imul(al3, bl1)) | 0;
  mid = (mid + Math.imul(al3, bh1)) | 0;
  mid = (mid + Math.imul(ah3, bl1)) | 0;
  hi = (hi + Math.imul(ah3, bh1)) | 0;
  lo = (lo + Math.imul(al2, bl2)) | 0;
  mid = (mid + Math.imul(al2, bh2)) | 0;
  mid = (mid + Math.imul(ah2, bl2)) | 0;
  hi = (hi + Math.imul(ah2, bh2)) | 0;
  lo = (lo + Math.imul(al1, bl3)) | 0;
  mid = (mid + Math.imul(al1, bh3)) | 0;
  mid = (mid + Math.imul(ah1, bl3)) | 0;
  hi = (hi + Math.imul(ah1, bh3)) | 0;
  lo = (lo + Math.imul(al0, bl4)) | 0;
  mid = (mid + Math.imul(al0, bh4)) | 0;
  mid = (mid + Math.imul(ah0, bl4)) | 0;
  hi = (hi + Math.imul(ah0, bh4)) | 0;

  let w4 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w4 >>> 26)) | 0;
  w4 &= 0x3ffffff;

  /* k = 5 */
  lo = Math.imul(al5, bl0);
  mid = Math.imul(al5, bh0);
  mid = (mid + Math.imul(ah5, bl0)) | 0;
  hi = Math.imul(ah5, bh0);
  lo = (lo + Math.imul(al4, bl1)) | 0;
  mid = (mid + Math.imul(al4, bh1)) | 0;
  mid = (mid + Math.imul(ah4, bl1)) | 0;
  hi = (hi + Math.imul(ah4, bh1)) | 0;
  lo = (lo + Math.imul(al3, bl2)) | 0;
  mid = (mid + Math.imul(al3, bh2)) | 0;
  mid = (mid + Math.imul(ah3, bl2)) | 0;
  hi = (hi + Math.imul(ah3, bh2)) | 0;
  lo = (lo + Math.imul(al2, bl3)) | 0;
  mid = (mid + Math.imul(al2, bh3)) | 0;
  mid = (mid + Math.imul(ah2, bl3)) | 0;
  hi = (hi + Math.imul(ah2, bh3)) | 0;
  lo = (lo + Math.imul(al1, bl4)) | 0;
  mid = (mid + Math.imul(al1, bh4)) | 0;
  mid = (mid + Math.imul(ah1, bl4)) | 0;
  hi = (hi + Math.imul(ah1, bh4)) | 0;
  lo = (lo + Math.imul(al0, bl5)) | 0;
  mid = (mid + Math.imul(al0, bh5)) | 0;
  mid = (mid + Math.imul(ah0, bl5)) | 0;
  hi = (hi + Math.imul(ah0, bh5)) | 0;

  let w5 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w5 >>> 26)) | 0;
  w5 &= 0x3ffffff;

  /* k = 6 */
  lo = Math.imul(al6, bl0);
  mid = Math.imul(al6, bh0);
  mid = (mid + Math.imul(ah6, bl0)) | 0;
  hi = Math.imul(ah6, bh0);
  lo = (lo + Math.imul(al5, bl1)) | 0;
  mid = (mid + Math.imul(al5, bh1)) | 0;
  mid = (mid + Math.imul(ah5, bl1)) | 0;
  hi = (hi + Math.imul(ah5, bh1)) | 0;
  lo = (lo + Math.imul(al4, bl2)) | 0;
  mid = (mid + Math.imul(al4, bh2)) | 0;
  mid = (mid + Math.imul(ah4, bl2)) | 0;
  hi = (hi + Math.imul(ah4, bh2)) | 0;
  lo = (lo + Math.imul(al3, bl3)) | 0;
  mid = (mid + Math.imul(al3, bh3)) | 0;
  mid = (mid + Math.imul(ah3, bl3)) | 0;
  hi = (hi + Math.imul(ah3, bh3)) | 0;
  lo = (lo + Math.imul(al2, bl4)) | 0;
  mid = (mid + Math.imul(al2, bh4)) | 0;
  mid = (mid + Math.imul(ah2, bl4)) | 0;
  hi = (hi + Math.imul(ah2, bh4)) | 0;
  lo = (lo + Math.imul(al1, bl5)) | 0;
  mid = (mid + Math.imul(al1, bh5)) | 0;
  mid = (mid + Math.imul(ah1, bl5)) | 0;
  hi = (hi + Math.imul(ah1, bh5)) | 0;
  lo = (lo + Math.imul(al0, bl6)) | 0;
  mid = (mid + Math.imul(al0, bh6)) | 0;
  mid = (mid + Math.imul(ah0, bl6)) | 0;
  hi = (hi + Math.imul(ah0, bh6)) | 0;

  let w6 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w6 >>> 26)) | 0;
  w6 &= 0x3ffffff;

  /* k = 7 */
  lo = Math.imul(al7, bl0);
  mid = Math.imul(al7, bh0);
  mid = (mid + Math.imul(ah7, bl0)) | 0;
  hi = Math.imul(ah7, bh0);
  lo = (lo + Math.imul(al6, bl1)) | 0;
  mid = (mid + Math.imul(al6, bh1)) | 0;
  mid = (mid + Math.imul(ah6, bl1)) | 0;
  hi = (hi + Math.imul(ah6, bh1)) | 0;
  lo = (lo + Math.imul(al5, bl2)) | 0;
  mid = (mid + Math.imul(al5, bh2)) | 0;
  mid = (mid + Math.imul(ah5, bl2)) | 0;
  hi = (hi + Math.imul(ah5, bh2)) | 0;
  lo = (lo + Math.imul(al4, bl3)) | 0;
  mid = (mid + Math.imul(al4, bh3)) | 0;
  mid = (mid + Math.imul(ah4, bl3)) | 0;
  hi = (hi + Math.imul(ah4, bh3)) | 0;
  lo = (lo + Math.imul(al3, bl4)) | 0;
  mid = (mid + Math.imul(al3, bh4)) | 0;
  mid = (mid + Math.imul(ah3, bl4)) | 0;
  hi = (hi + Math.imul(ah3, bh4)) | 0;
  lo = (lo + Math.imul(al2, bl5)) | 0;
  mid = (mid + Math.imul(al2, bh5)) | 0;
  mid = (mid + Math.imul(ah2, bl5)) | 0;
  hi = (hi + Math.imul(ah2, bh5)) | 0;
  lo = (lo + Math.imul(al1, bl6)) | 0;
  mid = (mid + Math.imul(al1, bh6)) | 0;
  mid = (mid + Math.imul(ah1, bl6)) | 0;
  hi = (hi + Math.imul(ah1, bh6)) | 0;
  lo = (lo + Math.imul(al0, bl7)) | 0;
  mid = (mid + Math.imul(al0, bh7)) | 0;
  mid = (mid + Math.imul(ah0, bl7)) | 0;
  hi = (hi + Math.imul(ah0, bh7)) | 0;

  let w7 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w7 >>> 26)) | 0;
  w7 &= 0x3ffffff;

  /* k = 8 */
  lo = Math.imul(al8, bl0);
  mid = Math.imul(al8, bh0);
  mid = (mid + Math.imul(ah8, bl0)) | 0;
  hi = Math.imul(ah8, bh0);
  lo = (lo + Math.imul(al7, bl1)) | 0;
  mid = (mid + Math.imul(al7, bh1)) | 0;
  mid = (mid + Math.imul(ah7, bl1)) | 0;
  hi = (hi + Math.imul(ah7, bh1)) | 0;
  lo = (lo + Math.imul(al6, bl2)) | 0;
  mid = (mid + Math.imul(al6, bh2)) | 0;
  mid = (mid + Math.imul(ah6, bl2)) | 0;
  hi = (hi + Math.imul(ah6, bh2)) | 0;
  lo = (lo + Math.imul(al5, bl3)) | 0;
  mid = (mid + Math.imul(al5, bh3)) | 0;
  mid = (mid + Math.imul(ah5, bl3)) | 0;
  hi = (hi + Math.imul(ah5, bh3)) | 0;
  lo = (lo + Math.imul(al4, bl4)) | 0;
  mid = (mid + Math.imul(al4, bh4)) | 0;
  mid = (mid + Math.imul(ah4, bl4)) | 0;
  hi = (hi + Math.imul(ah4, bh4)) | 0;
  lo = (lo + Math.imul(al3, bl5)) | 0;
  mid = (mid + Math.imul(al3, bh5)) | 0;
  mid = (mid + Math.imul(ah3, bl5)) | 0;
  hi = (hi + Math.imul(ah3, bh5)) | 0;
  lo = (lo + Math.imul(al2, bl6)) | 0;
  mid = (mid + Math.imul(al2, bh6)) | 0;
  mid = (mid + Math.imul(ah2, bl6)) | 0;
  hi = (hi + Math.imul(ah2, bh6)) | 0;
  lo = (lo + Math.imul(al1, bl7)) | 0;
  mid = (mid + Math.imul(al1, bh7)) | 0;
  mid = (mid + Math.imul(ah1, bl7)) | 0;
  hi = (hi + Math.imul(ah1, bh7)) | 0;
  lo = (lo + Math.imul(al0, bl8)) | 0;
  mid = (mid + Math.imul(al0, bh8)) | 0;
  mid = (mid + Math.imul(ah0, bl8)) | 0;
  hi = (hi + Math.imul(ah0, bh8)) | 0;

  let w8 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w8 >>> 26)) | 0;
  w8 &= 0x3ffffff;

  /* k = 9 */
  lo = Math.imul(al9, bl0);
  mid = Math.imul(al9, bh0);
  mid = (mid + Math.imul(ah9, bl0)) | 0;
  hi = Math.imul(ah9, bh0);
  lo = (lo + Math.imul(al8, bl1)) | 0;
  mid = (mid + Math.imul(al8, bh1)) | 0;
  mid = (mid + Math.imul(ah8, bl1)) | 0;
  hi = (hi + Math.imul(ah8, bh1)) | 0;
  lo = (lo + Math.imul(al7, bl2)) | 0;
  mid = (mid + Math.imul(al7, bh2)) | 0;
  mid = (mid + Math.imul(ah7, bl2)) | 0;
  hi = (hi + Math.imul(ah7, bh2)) | 0;
  lo = (lo + Math.imul(al6, bl3)) | 0;
  mid = (mid + Math.imul(al6, bh3)) | 0;
  mid = (mid + Math.imul(ah6, bl3)) | 0;
  hi = (hi + Math.imul(ah6, bh3)) | 0;
  lo = (lo + Math.imul(al5, bl4)) | 0;
  mid = (mid + Math.imul(al5, bh4)) | 0;
  mid = (mid + Math.imul(ah5, bl4)) | 0;
  hi = (hi + Math.imul(ah5, bh4)) | 0;
  lo = (lo + Math.imul(al4, bl5)) | 0;
  mid = (mid + Math.imul(al4, bh5)) | 0;
  mid = (mid + Math.imul(ah4, bl5)) | 0;
  hi = (hi + Math.imul(ah4, bh5)) | 0;
  lo = (lo + Math.imul(al3, bl6)) | 0;
  mid = (mid + Math.imul(al3, bh6)) | 0;
  mid = (mid + Math.imul(ah3, bl6)) | 0;
  hi = (hi + Math.imul(ah3, bh6)) | 0;
  lo = (lo + Math.imul(al2, bl7)) | 0;
  mid = (mid + Math.imul(al2, bh7)) | 0;
  mid = (mid + Math.imul(ah2, bl7)) | 0;
  hi = (hi + Math.imul(ah2, bh7)) | 0;
  lo = (lo + Math.imul(al1, bl8)) | 0;
  mid = (mid + Math.imul(al1, bh8)) | 0;
  mid = (mid + Math.imul(ah1, bl8)) | 0;
  hi = (hi + Math.imul(ah1, bh8)) | 0;
  lo = (lo + Math.imul(al0, bl9)) | 0;
  mid = (mid + Math.imul(al0, bh9)) | 0;
  mid = (mid + Math.imul(ah0, bl9)) | 0;
  hi = (hi + Math.imul(ah0, bh9)) | 0;

  let w9 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w9 >>> 26)) | 0;
  w9 &= 0x3ffffff;

  /* k = 10 */
  lo = Math.imul(al9, bl1);
  mid = Math.imul(al9, bh1);
  mid = (mid + Math.imul(ah9, bl1)) | 0;
  hi = Math.imul(ah9, bh1);
  lo = (lo + Math.imul(al8, bl2)) | 0;
  mid = (mid + Math.imul(al8, bh2)) | 0;
  mid = (mid + Math.imul(ah8, bl2)) | 0;
  hi = (hi + Math.imul(ah8, bh2)) | 0;
  lo = (lo + Math.imul(al7, bl3)) | 0;
  mid = (mid + Math.imul(al7, bh3)) | 0;
  mid = (mid + Math.imul(ah7, bl3)) | 0;
  hi = (hi + Math.imul(ah7, bh3)) | 0;
  lo = (lo + Math.imul(al6, bl4)) | 0;
  mid = (mid + Math.imul(al6, bh4)) | 0;
  mid = (mid + Math.imul(ah6, bl4)) | 0;
  hi = (hi + Math.imul(ah6, bh4)) | 0;
  lo = (lo + Math.imul(al5, bl5)) | 0;
  mid = (mid + Math.imul(al5, bh5)) | 0;
  mid = (mid + Math.imul(ah5, bl5)) | 0;
  hi = (hi + Math.imul(ah5, bh5)) | 0;
  lo = (lo + Math.imul(al4, bl6)) | 0;
  mid = (mid + Math.imul(al4, bh6)) | 0;
  mid = (mid + Math.imul(ah4, bl6)) | 0;
  hi = (hi + Math.imul(ah4, bh6)) | 0;
  lo = (lo + Math.imul(al3, bl7)) | 0;
  mid = (mid + Math.imul(al3, bh7)) | 0;
  mid = (mid + Math.imul(ah3, bl7)) | 0;
  hi = (hi + Math.imul(ah3, bh7)) | 0;
  lo = (lo + Math.imul(al2, bl8)) | 0;
  mid = (mid + Math.imul(al2, bh8)) | 0;
  mid = (mid + Math.imul(ah2, bl8)) | 0;
  hi = (hi + Math.imul(ah2, bh8)) | 0;
  lo = (lo + Math.imul(al1, bl9)) | 0;
  mid = (mid + Math.imul(al1, bh9)) | 0;
  mid = (mid + Math.imul(ah1, bl9)) | 0;
  hi = (hi + Math.imul(ah1, bh9)) | 0;

  let w10 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w10 >>> 26)) | 0;
  w10 &= 0x3ffffff;

  /* k = 11 */
  lo = Math.imul(al9, bl2);
  mid = Math.imul(al9, bh2);
  mid = (mid + Math.imul(ah9, bl2)) | 0;
  hi = Math.imul(ah9, bh2);
  lo = (lo + Math.imul(al8, bl3)) | 0;
  mid = (mid + Math.imul(al8, bh3)) | 0;
  mid = (mid + Math.imul(ah8, bl3)) | 0;
  hi = (hi + Math.imul(ah8, bh3)) | 0;
  lo = (lo + Math.imul(al7, bl4)) | 0;
  mid = (mid + Math.imul(al7, bh4)) | 0;
  mid = (mid + Math.imul(ah7, bl4)) | 0;
  hi = (hi + Math.imul(ah7, bh4)) | 0;
  lo = (lo + Math.imul(al6, bl5)) | 0;
  mid = (mid + Math.imul(al6, bh5)) | 0;
  mid = (mid + Math.imul(ah6, bl5)) | 0;
  hi = (hi + Math.imul(ah6, bh5)) | 0;
  lo = (lo + Math.imul(al5, bl6)) | 0;
  mid = (mid + Math.imul(al5, bh6)) | 0;
  mid = (mid + Math.imul(ah5, bl6)) | 0;
  hi = (hi + Math.imul(ah5, bh6)) | 0;
  lo = (lo + Math.imul(al4, bl7)) | 0;
  mid = (mid + Math.imul(al4, bh7)) | 0;
  mid = (mid + Math.imul(ah4, bl7)) | 0;
  hi = (hi + Math.imul(ah4, bh7)) | 0;
  lo = (lo + Math.imul(al3, bl8)) | 0;
  mid = (mid + Math.imul(al3, bh8)) | 0;
  mid = (mid + Math.imul(ah3, bl8)) | 0;
  hi = (hi + Math.imul(ah3, bh8)) | 0;
  lo = (lo + Math.imul(al2, bl9)) | 0;
  mid = (mid + Math.imul(al2, bh9)) | 0;
  mid = (mid + Math.imul(ah2, bl9)) | 0;
  hi = (hi + Math.imul(ah2, bh9)) | 0;

  let w11 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w11 >>> 26)) | 0;
  w11 &= 0x3ffffff;

  /* k = 12 */
  lo = Math.imul(al9, bl3);
  mid = Math.imul(al9, bh3);
  mid = (mid + Math.imul(ah9, bl3)) | 0;
  hi = Math.imul(ah9, bh3);
  lo = (lo + Math.imul(al8, bl4)) | 0;
  mid = (mid + Math.imul(al8, bh4)) | 0;
  mid = (mid + Math.imul(ah8, bl4)) | 0;
  hi = (hi + Math.imul(ah8, bh4)) | 0;
  lo = (lo + Math.imul(al7, bl5)) | 0;
  mid = (mid + Math.imul(al7, bh5)) | 0;
  mid = (mid + Math.imul(ah7, bl5)) | 0;
  hi = (hi + Math.imul(ah7, bh5)) | 0;
  lo = (lo + Math.imul(al6, bl6)) | 0;
  mid = (mid + Math.imul(al6, bh6)) | 0;
  mid = (mid + Math.imul(ah6, bl6)) | 0;
  hi = (hi + Math.imul(ah6, bh6)) | 0;
  lo = (lo + Math.imul(al5, bl7)) | 0;
  mid = (mid + Math.imul(al5, bh7)) | 0;
  mid = (mid + Math.imul(ah5, bl7)) | 0;
  hi = (hi + Math.imul(ah5, bh7)) | 0;
  lo = (lo + Math.imul(al4, bl8)) | 0;
  mid = (mid + Math.imul(al4, bh8)) | 0;
  mid = (mid + Math.imul(ah4, bl8)) | 0;
  hi = (hi + Math.imul(ah4, bh8)) | 0;
  lo = (lo + Math.imul(al3, bl9)) | 0;
  mid = (mid + Math.imul(al3, bh9)) | 0;
  mid = (mid + Math.imul(ah3, bl9)) | 0;
  hi = (hi + Math.imul(ah3, bh9)) | 0;

  let w12 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w12 >>> 26)) | 0;
  w12 &= 0x3ffffff;

  /* k = 13 */
  lo = Math.imul(al9, bl4);
  mid = Math.imul(al9, bh4);
  mid = (mid + Math.imul(ah9, bl4)) | 0;
  hi = Math.imul(ah9, bh4);
  lo = (lo + Math.imul(al8, bl5)) | 0;
  mid = (mid + Math.imul(al8, bh5)) | 0;
  mid = (mid + Math.imul(ah8, bl5)) | 0;
  hi = (hi + Math.imul(ah8, bh5)) | 0;
  lo = (lo + Math.imul(al7, bl6)) | 0;
  mid = (mid + Math.imul(al7, bh6)) | 0;
  mid = (mid + Math.imul(ah7, bl6)) | 0;
  hi = (hi + Math.imul(ah7, bh6)) | 0;
  lo = (lo + Math.imul(al6, bl7)) | 0;
  mid = (mid + Math.imul(al6, bh7)) | 0;
  mid = (mid + Math.imul(ah6, bl7)) | 0;
  hi = (hi + Math.imul(ah6, bh7)) | 0;
  lo = (lo + Math.imul(al5, bl8)) | 0;
  mid = (mid + Math.imul(al5, bh8)) | 0;
  mid = (mid + Math.imul(ah5, bl8)) | 0;
  hi = (hi + Math.imul(ah5, bh8)) | 0;
  lo = (lo + Math.imul(al4, bl9)) | 0;
  mid = (mid + Math.imul(al4, bh9)) | 0;
  mid = (mid + Math.imul(ah4, bl9)) | 0;
  hi = (hi + Math.imul(ah4, bh9)) | 0;

  let w13 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w13 >>> 26)) | 0;
  w13 &= 0x3ffffff;

  /* k = 14 */
  lo = Math.imul(al9, bl5);
  mid = Math.imul(al9, bh5);
  mid = (mid + Math.imul(ah9, bl5)) | 0;
  hi = Math.imul(ah9, bh5);
  lo = (lo + Math.imul(al8, bl6)) | 0;
  mid = (mid + Math.imul(al8, bh6)) | 0;
  mid = (mid + Math.imul(ah8, bl6)) | 0;
  hi = (hi + Math.imul(ah8, bh6)) | 0;
  lo = (lo + Math.imul(al7, bl7)) | 0;
  mid = (mid + Math.imul(al7, bh7)) | 0;
  mid = (mid + Math.imul(ah7, bl7)) | 0;
  hi = (hi + Math.imul(ah7, bh7)) | 0;
  lo = (lo + Math.imul(al6, bl8)) | 0;
  mid = (mid + Math.imul(al6, bh8)) | 0;
  mid = (mid + Math.imul(ah6, bl8)) | 0;
  hi = (hi + Math.imul(ah6, bh8)) | 0;
  lo = (lo + Math.imul(al5, bl9)) | 0;
  mid = (mid + Math.imul(al5, bh9)) | 0;
  mid = (mid + Math.imul(ah5, bl9)) | 0;
  hi = (hi + Math.imul(ah5, bh9)) | 0;

  let w14 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w14 >>> 26)) | 0;
  w14 &= 0x3ffffff;

  /* k = 15 */
  lo = Math.imul(al9, bl6);
  mid = Math.imul(al9, bh6);
  mid = (mid + Math.imul(ah9, bl6)) | 0;
  hi = Math.imul(ah9, bh6);
  lo = (lo + Math.imul(al8, bl7)) | 0;
  mid = (mid + Math.imul(al8, bh7)) | 0;
  mid = (mid + Math.imul(ah8, bl7)) | 0;
  hi = (hi + Math.imul(ah8, bh7)) | 0;
  lo = (lo + Math.imul(al7, bl8)) | 0;
  mid = (mid + Math.imul(al7, bh8)) | 0;
  mid = (mid + Math.imul(ah7, bl8)) | 0;
  hi = (hi + Math.imul(ah7, bh8)) | 0;
  lo = (lo + Math.imul(al6, bl9)) | 0;
  mid = (mid + Math.imul(al6, bh9)) | 0;
  mid = (mid + Math.imul(ah6, bl9)) | 0;
  hi = (hi + Math.imul(ah6, bh9)) | 0;

  let w15 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w15 >>> 26)) | 0;
  w15 &= 0x3ffffff;

  /* k = 16 */
  lo = Math.imul(al9, bl7);
  mid = Math.imul(al9, bh7);
  mid = (mid + Math.imul(ah9, bl7)) | 0;
  hi = Math.imul(ah9, bh7);
  lo = (lo + Math.imul(al8, bl8)) | 0;
  mid = (mid + Math.imul(al8, bh8)) | 0;
  mid = (mid + Math.imul(ah8, bl8)) | 0;
  hi = (hi + Math.imul(ah8, bh8)) | 0;
  lo = (lo + Math.imul(al7, bl9)) | 0;
  mid = (mid + Math.imul(al7, bh9)) | 0;
  mid = (mid + Math.imul(ah7, bl9)) | 0;
  hi = (hi + Math.imul(ah7, bh9)) | 0;

  let w16 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w16 >>> 26)) | 0;
  w16 &= 0x3ffffff;

  /* k = 17 */
  lo = Math.imul(al9, bl8);
  mid = Math.imul(al9, bh8);
  mid = (mid + Math.imul(ah9, bl8)) | 0;
  hi = Math.imul(ah9, bh8);
  lo = (lo + Math.imul(al8, bl9)) | 0;
  mid = (mid + Math.imul(al8, bh9)) | 0;
  mid = (mid + Math.imul(ah8, bl9)) | 0;
  hi = (hi + Math.imul(ah8, bh9)) | 0;

  let w17 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w17 >>> 26)) | 0;
  w17 &= 0x3ffffff;

  /* k = 18 */
  lo = Math.imul(al9, bl9);
  mid = Math.imul(al9, bh9);
  mid = (mid + Math.imul(ah9, bl9)) | 0;
  hi = Math.imul(ah9, bh9);

  let w18 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
  c = (((hi + (mid >>> 13)) | 0) + (w18 >>> 26)) | 0;
  w18 &= 0x3ffffff;

  o[0] = w0;
  o[1] = w1;
  o[2] = w2;
  o[3] = w3;
  o[4] = w4;
  o[5] = w5;
  o[6] = w6;
  o[7] = w7;
  o[8] = w8;
  o[9] = w9;
  o[10] = w10;
  o[11] = w11;
  o[12] = w12;
  o[13] = w13;
  o[14] = w14;
  o[15] = w15;
  o[16] = w16;
  o[17] = w17;
  o[18] = w18;

  if (c !== 0) {
    o[19] = c;
    out.length += 1;
  }

  // Note: we shouldn't need to strip here.
  return out;
}

// Polyfill comb.
if (!Math.imul)
  comb10MulTo = smallMulTo;

/*
 * Expose
 */

BN.Red = Red;

module.exports = BN;
}],
[/* 33 */ 'bcrypto', '/lib/internal/custom-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * custom.js - custom inspect symbol for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

exports.custom = 'inspect';
}],
[/* 34 */ 'bcrypto', '/lib/internal/asn1.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * asn1.js - asn1 parsing for bcrypto
 * Copyright (c) 2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('assert');
const BN = __node_require__(31 /* '../bn' */);

/*
 * ASN1
 */

function readSize(data, pos, strict) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(typeof strict === 'boolean');

  if (pos >= data.length)
    throw new Error('Invalid size.');

  const field = data[pos];
  const bytes = field & 0x7f;

  pos += 1;

  // Definite form.
  if ((field & 0x80) === 0) {
    // Short form.
    return [bytes, pos];
  }

  // Indefinite form.
  if (strict && bytes === 0)
    throw new Error('Indefinite length.');

  // Long form.
  let size = 0;

  for (let i = 0; i < bytes; i++) {
    assert(pos < data.length);

    const ch = data[pos];

    pos += 1;

    if (size >= (1 << 24))
      throw new Error('Length too large.');

    size *= 0x100;
    size += ch;

    if (strict && size === 0)
      throw new Error('Unexpected leading zeroes.');
  }

  if (strict && size < 0x80)
    throw new Error('Non-minimal length.');

  return [size, pos];
}

function readSeq(data, pos, strict = true) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(typeof strict === 'boolean');

  if (pos >= data.length || data[pos] !== 0x30)
    throw new Error('Invalid sequence tag.');

  pos += 1;

  let size;
  [size, pos] = readSize(data, pos, strict);

  if (strict && pos + size !== data.length)
    throw new Error('Trailing bytes.');

  return pos;
}

function readInt(data, pos, strict = true) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(typeof strict === 'boolean');

  if (pos >= data.length || data[pos] !== 0x02)
    throw new Error('Invalid integer tag.');

  pos += 1;

  let size;
  [size, pos] = readSize(data, pos, strict);

  if (pos + size > data.length)
    throw new Error('Integer body out of bounds.');

  if (strict) {
    // Zero length integer.
    if (size === 0)
      throw new Error('Zero length integer.');

    // No negatives.
    if (data[pos] & 0x80)
      throw new Error('Integers must be positive.');

    // Allow zero only if it prefixes a high bit.
    if (size > 1) {
      if (data[pos] === 0x00 && (data[pos + 1] & 0x80) === 0x00)
        throw new Error('Unexpected leading zeroes.');
    }
  }

  // Eat leading zeroes.
  while (size > 0 && data[pos] === 0x00) {
    pos += 1;
    size -= 1;
  }

  // No reason to have an integer larger than this.
  if (size > 2048)
    throw new Error('Invalid integer size.');

  const num = BN.decode(data.slice(pos, pos + size));

  pos += size;

  return [num, pos];
}

function readVersion(data, pos, version, strict = true) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert((version & 0xff) === version);
  assert(typeof strict === 'boolean');

  let num;
  [num, pos] = readInt(data, pos, strict);

  if (num.cmpn(version) !== 0)
    throw new Error('Invalid version.');

  return pos;
}

function sizeSize(size) {
  assert((size >>> 0) === size);

  if (size <= 0x7f) // [size]
    return 1;

  if (size <= 0xff) // 0x81 [size]
    return 2;

  assert(size <= 0xffff);

  return 3; // 0x82 [size-hi] [size-lo]
}

function sizeSeq(size) {
  return 1 + sizeSize(size) + size;
}

function sizeInt(num) {
  assert(num instanceof BN);

  // 0x02 [size] [0x00?] [int]
  const bits = num.bitLength();

  let size = (bits + 7) >>> 3;

  if (bits > 0 && (bits & 7) === 0)
    size += num.testn(bits - 1);

  if (bits === 0)
    size = 1;

  return 1 + sizeSize(size) + size;
}

function sizeVersion(version) {
  assert((version & 0xff) === version);
  return 3;
}

function writeSize(data, pos, size) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert((size >>> 0) === size);

  if (size <= 0x7f)  {
    // [size]
    data[pos++] = size;
  } else if (size <= 0xff) {
    // 0x81 [size]
    data[pos++] = 0x81;
    data[pos++] = size;
  } else {
    // 0x82 [size-hi] [size-lo]
    assert(size <= 0xffff);
    data[pos++] = 0x82;
    data[pos++] = size >> 8;
    data[pos++] = size & 0xff;
  }

  assert(pos <= data.length);

  return pos;
}

function writeSeq(data, pos, size) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);

  data[pos++] = 0x30;

  return writeSize(data, pos, size);
}

function writeInt(data, pos, num) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(num instanceof BN);

  // 0x02 [size] [0x00?] [int]
  const bits = num.bitLength();

  let size = (bits + 7) >>> 3;
  let pad = 0;

  if (bits > 0 && (bits & 7) === 0)
    pad = num.testn(bits - 1);

  if (bits === 0)
    size = 1;

  data[pos++] = 0x02;

  pos = writeSize(data, pos, pad + size);

  if (pad)
    data[pos++] = 0x00;

  if (bits !== 0)
    num.encode().copy(data, pos);
  else
    data[pos] = 0x00;

  pos += size;

  assert(pos <= data.length);

  return pos;
}

function writeVersion(data, pos, version) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert((version & 0xff) === version);
  assert(pos + 3 <= data.length);

  data[pos++] = 0x02;
  data[pos++] = 0x01;
  data[pos++] = version;

  return pos;
}

/*
 * Expose
 */

exports.readSize = readSize;
exports.readSeq = readSeq;
exports.readInt = readInt;
exports.readVersion = readVersion;
exports.sizeSize = sizeSize;
exports.sizeSeq = sizeSeq;
exports.sizeInt = sizeInt;
exports.sizeVersion = sizeVersion;
exports.writeSize = writeSize;
exports.writeSeq = writeSeq;
exports.writeInt = writeInt;
exports.writeVersion = writeVersion;
}],
[/* 35 */ 'bcrypto', '/lib/js/schnorr-legacy.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * schnorr-legacy.js - bip-schnorr for bcrypto
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bip-schnorr:
 *   Copyright (c) 2018-2019, Pieter Wuille (2-clause BSD License).
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/reference.py
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * Resources:
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/reference.py
 *   https://github.com/sipa/bips/blob/d194620/bip-schnorr/test-vectors.csv
 *   https://github.com/ElementsProject/secp256k1-zkp/tree/11af701/src/modules/schnorrsig
 *   https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/2019-05-15-schnorr.md
 *
 * References:
 *
 *   [SCHNORR] Schnorr Signatures for secp256k1
 *     Pieter Wuille
 *     https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *
 *   [CASH] Schnorr Signature specification
 *     Mark B. Lundeberg
 *     https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/2019-05-15-schnorr.md
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const BatchRNG = __node_require__(36 /* './batch-rng' */);
const BN = __node_require__(31 /* '../bn' */);

/**
 * Schnorr
 */

class Schnorr {
  constructor(curve, hash) {
    this.curve = curve;
    this.hash = hash;
    this.rng = new BatchRNG(this.curve, this.encode.bind(this));
  }

  check() {
    // [SCHNORR] "Footnotes".
    // Must be congruent to 3 mod 4.
    if (this.curve.p.andln(3) !== 3)
      throw new Error(`Schnorr is not supported for ${this.curve.id}.`);
  }

  encode(key) {
    // Extra speedy key reserialization.
    assert(Buffer.isBuffer(key));

    const {fieldSize} = this.curve;

    if (key.length === 1 + fieldSize)
      return key;

    if (key.length !== 1 + fieldSize * 2)
      throw new Error('Invalid point.');

    const out = Buffer.alloc(1 + fieldSize);

    out[0] = 0x02 | (key[key.length - 1] & 1);
    key.copy(out, 1, 1, 1 + fieldSize);

    return out;
  }

  hashInt(...items) {
    // [SCHNORR] "Specification".
    // eslint-disable-next-line
    const h = new this.hash();

    h.init();

    for (const item of items)
      h.update(item);

    let hash = h.final(this.curve.scalarSize);

    if (hash.length > this.curve.scalarSize)
      hash = hash.slice(0, this.curve.scalarSize);

    const num = BN.decode(hash, this.curve.endian);

    num.iumaskn(this.curve.scalarBits);

    return num.imod(this.curve.n);
  }

  hashNonce(a, m) {
    return this.hashInt(a, m);
  }

  hashChallenge(R, A, m) {
    return this.hashInt(R, this.encode(A), m);
  }

  sign(msg, key) {
    assert(Buffer.isBuffer(msg));

    this.check();

    return this._sign(msg, key);
  }

  _sign(msg, key) {
    // Schnorr Signing.
    //
    // [SCHNORR] "Signing".
    // [CASH] "Recommended practices for secure signature generation".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `a` be a secret non-zero scalar.
    //   - k != 0.
    //
    // Computation:
    //
    //   A = G * a
    //   k = H(a, m) mod n
    //   R = G * k
    //   k = -k mod n, if y(R) is not square
    //   r = x(R)
    //   e = H(r, A, m) mod n
    //   s = (k + e * a) mod n
    //   S = (r, s)
    //
    // Note that `k` must remain secret,
    // otherwise an attacker can compute:
    //
    //   a = (s - k) / e mod n
    const {n} = this.curve;
    const G = this.curve.g;
    const a = this.curve.decodeScalar(key);

    if (a.isZero() || a.cmp(n) >= 0)
      throw new Error('Invalid private key.');

    const A = G.mulBlind(a);
    const k = this.hashNonce(key, msg);

    if (k.isZero())
      throw new Error('Signing failed (k\' = 0).');

    const R = G.mulBlind(k);

    if (!R.isSquare())
      k.ineg().imod(n);

    const Rraw = R.encodeX();
    const Araw = A.encode();
    const e = this.hashChallenge(Rraw, Araw, msg);
    const s = k.add(e.mul(a)).imod(n);

    return Buffer.concat([Rraw, this.curve.encodeScalar(s)]);
  }

  verify(msg, sig, key) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));
    assert(Buffer.isBuffer(key));

    this.check();

    if (sig.length !== this.curve.fieldSize + this.curve.scalarSize)
      return false;

    try {
      return this._verify(msg, sig, key);
    } catch (e) {
      return false;
    }
  }

  _verify(msg, sig, key) {
    // Schnorr Verification.
    //
    // [SCHNORR] "Verification".
    // [CASH] "Signature verification algorithm".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `r` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - r^3 + a * r + b is square in F(p).
    //   - sqrt(r^3 + a * r + b) is square in F(p).
    //   - r < p, s < n.
    //   - R != O.
    //
    // Computation:
    //
    //   R = (r, sqrt(r^3 + a * r + b))
    //   e = H(r, A, m) mod n
    //   R == G * s - A * e
    //
    // We can skip a square root with:
    //
    //   e = H(r, A, m) mod n
    //   R = G * s - A * e
    //   y(R) is square
    //   x(R) == r
    //
    // We can also avoid affinization by
    // replacing the two assertions with:
    //
    //   (y(R) * z(R) mod p) is square
    //   x(R) == r * z(R)^2 mod p
    //
    // Furthermore, squareness can be calculated
    // with a variable time Jacobi symbol algorithm.
    const {p, n} = this.curve;
    const G = this.curve.g;
    const Rraw = sig.slice(0, this.curve.fieldSize);
    const sraw = sig.slice(this.curve.fieldSize);
    const r = this.curve.decodeField(Rraw);
    const s = this.curve.decodeScalar(sraw);
    const A = this.curve.decodePoint(key);

    if (r.cmp(p) >= 0 || s.cmp(n) >= 0)
      return false;

    const e = this.hashChallenge(Rraw, key, msg);
    const R = G.jmulAdd(s, A, e.ineg().imod(n));

    if (!R.isSquare())
      return false;

    if (!R.eqX(r))
      return false;

    return true;
  }

  verifyBatch(batch) {
    assert(Array.isArray(batch));

    this.check();

    for (const item of batch) {
      assert(Array.isArray(item) && item.length === 3);

      const [msg, sig, key] = item;

      assert(Buffer.isBuffer(msg));
      assert(Buffer.isBuffer(sig));
      assert(Buffer.isBuffer(key));

      if (sig.length !== this.curve.fieldSize + this.curve.scalarSize)
        return false;
    }

    try {
      return this._verifyBatch(batch);
    } catch (e) {
      return false;
    }
  }

  _verifyBatch(batch) {
    // Schnorr Batch Verification.
    //
    // [SCHNORR] "Batch Verification".
    //
    // Assumptions:
    //
    //   - Let `H` be a cryptographic hash function.
    //   - Let `m` be a 32-byte array.
    //   - Let `r` and `s` be signature elements.
    //   - Let `A` be a valid group element.
    //   - Let `i` be the batch item index.
    //   - r^3 + a * r + b is square in F(p).
    //   - sqrt(r^3 + a * r + b) is square in F(p).
    //   - r < p, s < n.
    //   - a1 = 1 mod n.
    //
    // Computation:
    //
    //   Ri = (ri, sqrt(ri^3 + a * ri + b))
    //   ei = H(ri, Ai, mi) mod n
    //   ai = random integer in [1,n-1]
    //   lhs = si * ai + ... mod n
    //   rhs = Ri * ai + Ai * (ei * ai mod n) + ...
    //   G * -lhs + rhs == O
    const {n} = this.curve;
    const G = this.curve.g;
    const points = new Array(1 + batch.length * 2);
    const coeffs = new Array(1 + batch.length * 2);
    const sum = new BN(0);

    this.rng.init(batch);

    points[0] = G;
    coeffs[0] = sum;

    for (let i = 0; i < batch.length; i++) {
      const [msg, sig, key] = batch[i];
      const Rraw = sig.slice(0, this.curve.fieldSize);
      const sraw = sig.slice(this.curve.fieldSize);
      const R = this.curve.decodeSquare(Rraw);
      const s = this.curve.decodeScalar(sraw);
      const A = this.curve.decodePoint(key);

      if (s.cmp(n) >= 0)
        return false;

      const e = this.hashChallenge(Rraw, key, msg);
      const a = this.rng.generate(i);
      const ea = e.mul(a).imod(n);

      sum.iadd(s.mul(a)).imod(n);

      points[1 + i * 2 + 0] = R;
      coeffs[1 + i * 2 + 0] = a;
      points[1 + i * 2 + 1] = A;
      coeffs[1 + i * 2 + 1] = ea;
    }

    sum.ineg().imod(n);

    return this.curve.jmulAll(points, coeffs).isInfinity();
  }
}

/*
 * Expose
 */

module.exports = Schnorr;
}],
[/* 36 */ 'bcrypto', '/lib/js/batch-rng.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * batch-rng.js - batch rng for bcrypto
 * Copyright (c) 2019-2020, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on ElementsProject/secp256k1-zkp:
 *   Copyright (c) 2013, Pieter Wuille.
 *   https://github.com/ElementsProject/secp256k1-zkp
 *
 * Resources:
 *   https://github.com/ElementsProject/secp256k1-zkp/blob/11af701/src/modules/schnorrsig/main_impl.h#L166
 *   https://github.com/ElementsProject/secp256k1-zkp/blob/11af701/src/scalar_4x64_impl.h#L972
 *   https://github.com/ElementsProject/secp256k1-zkp/blob/11af701/src/scalar_8x32_impl.h#L747
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const BN = __node_require__(31 /* '../bn' */);
const ChaCha20 = __node_require__(37 /* '../chacha20' */);
const SHA256 = __node_require__(39 /* '../sha256' */);

/**
 * BatchRNG
 */

class BatchRNG {
  constructor(curve, encode = key => key) {
    this.curve = curve;
    this.encode = encode;
    this.hash = new SHA256();
    this.chacha = new ChaCha20();
    this.key = Buffer.alloc(32, 0x00);
    this.iv = Buffer.alloc(8, 0x00);
    this.cache = [new BN(1), new BN(1)];
  }

  init(batch) {
    assert(Array.isArray(batch));

    this.hash.init();

    for (const [msg, sig, key] of batch) {
      this.hash.update(SHA256.digest(msg));
      this.hash.update(sig);
      this.hash.update(this.encode(key));
    }

    this.key = this.hash.final();
    this.cache[0] = new BN(1);
    this.cache[1] = new BN(1);

    return this;
  }

  encrypt(counter) {
    const size = this.curve.scalarSize * 2;
    const data = Buffer.alloc(size, 0x00);
    const left = data.slice(0, this.curve.scalarSize);
    const right = data.slice(this.curve.scalarSize);

    this.chacha.init(this.key, this.iv, counter);
    this.chacha.encrypt(data);

    return [
      this.curve.decodeScalar(left),
      this.curve.decodeScalar(right)
    ];
  }

  refresh(counter) {
    let overflow = 0;

    for (;;) {
      // First word is always zero.
      this.iv[4] = overflow;
      this.iv[5] = overflow >>> 8;
      this.iv[6] = overflow >>> 16;
      this.iv[7] = overflow >>> 24;

      overflow += 1;

      const [s1, s2] = this.encrypt(counter);

      if (s1.isZero() || s1.cmp(this.curve.n) >= 0)
        continue;

      if (s2.isZero() || s2.cmp(this.curve.n) >= 0)
        continue;

      this.cache[0] = s1;
      this.cache[1] = s2;

      break;
    }
  }

  generate(index) {
    assert((index >>> 0) === index);

    if (index & 1)
      this.refresh(index >>> 1);

    return this.cache[index & 1];
  }
}

/*
 * Expose
 */

module.exports = BatchRNG;
}],
[/* 37 */ 'bcrypto', '/lib/chacha20-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * chacha20.js - chacha20 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(38 /* './js/chacha20' */);
}],
[/* 38 */ 'bcrypto', '/lib/js/chacha20.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * chacha20.js - chacha20 for bcrypto
 * Copyright (c) 2016-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources
 *   https://en.wikipedia.org/wiki/Chacha20
 *   https://tools.ietf.org/html/rfc7539#section-2
 *   https://cr.yp.to/chacha.html
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);

/*
 * Constants
 */

const BIG_ENDIAN = new Int8Array(new Int16Array([1]).buffer)[0] === 0;

/**
 * ChaCha20
 */

class ChaCha20 {
  /**
   * Create a ChaCha20 context.
   * @constructor
   */

  constructor() {
    this.state = new Uint32Array(16);
    this.stream = new Uint32Array(16);
    this.bytes = new Uint8Array(this.stream.buffer);
    this.pos = -1;

    if (BIG_ENDIAN)
      this.bytes = Buffer.alloc(64);
  }

  /**
   * Initialize chacha20 with a key, nonce, and counter.
   * @param {Buffer} key
   * @param {Buffer} nonce
   * @param {Number} counter
   */

  init(key, nonce, counter) {
    if (counter == null)
      counter = 0;

    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));
    assert(Number.isSafeInteger(counter));

    if (key.length !== 16 && key.length !== 32)
      throw new RangeError('Invalid key size.');

    if (nonce.length >= 24) {
      key = ChaCha20.derive(key, nonce.slice(0, 16));
      nonce = nonce.slice(16);
    }

    this.state[0] = 0x61707865;
    this.state[1] = key.length < 32 ? 0x3120646e : 0x3320646e;
    this.state[2] = key.length < 32 ? 0x79622d36 : 0x79622d32;
    this.state[3] = 0x6b206574;
    this.state[4] = readU32(key, 0);
    this.state[5] = readU32(key, 4);
    this.state[6] = readU32(key, 8);
    this.state[7] = readU32(key, 12);
    this.state[8] = readU32(key, 16 % key.length);
    this.state[9] = readU32(key, 20 % key.length);
    this.state[10] = readU32(key, 24 % key.length);
    this.state[11] = readU32(key, 28 % key.length);
    this.state[12] = counter >>> 0;

    if (nonce.length === 8) {
      this.state[13] = (counter / 0x100000000) >>> 0;
      this.state[14] = readU32(nonce, 0);
      this.state[15] = readU32(nonce, 4);
    } else if (nonce.length === 12) {
      this.state[13] = readU32(nonce, 0);
      this.state[14] = readU32(nonce, 4);
      this.state[15] = readU32(nonce, 8);
    } else if (nonce.length === 16) {
      this.state[12] = readU32(nonce, 0);
      this.state[13] = readU32(nonce, 4);
      this.state[14] = readU32(nonce, 8);
      this.state[15] = readU32(nonce, 12);
    } else {
      throw new RangeError('Invalid nonce size.');
    }

    this.pos = 0;

    return this;
  }

  /**
   * Encrypt/decrypt data.
   * @param {Buffer} data - Will be mutated.
   * @returns {Buffer}
   */

  encrypt(data) {
    assert(Buffer.isBuffer(data));

    if (this.pos === -1)
      throw new Error('Context is not initialized.');

    for (let i = 0; i < data.length; i++) {
      if ((this.pos & 63) === 0) {
        this._block();
        this.pos = 0;
      }

      data[i] ^= this.bytes[this.pos++];
    }

    return data;
  }

  /**
   * Stir the stream.
   */

  _block() {
    for (let i = 0; i < 16; i++)
      this.stream[i] = this.state[i];

    for (let i = 0; i < 10; i++) {
      qround(this.stream, 0, 4, 8, 12);
      qround(this.stream, 1, 5, 9, 13);
      qround(this.stream, 2, 6, 10, 14);
      qround(this.stream, 3, 7, 11, 15);
      qround(this.stream, 0, 5, 10, 15);
      qround(this.stream, 1, 6, 11, 12);
      qround(this.stream, 2, 7, 8, 13);
      qround(this.stream, 3, 4, 9, 14);
    }

    for (let i = 0; i < 16; i++)
      this.stream[i] += this.state[i];

    if (BIG_ENDIAN) {
      for (let i = 0; i < 16; i++)
        writeU32(this.bytes, this.stream[i], i * 4);
    }

    this.state[12] += 1;

    if (this.state[12] === 0)
      this.state[13] += 1;
  }

  /**
   * Destroy context.
   */

  destroy() {
    for (let i = 0; i < 16; i++) {
      this.state[i] = 0;
      this.stream[i] = 0;
    }

    if (BIG_ENDIAN) {
      for (let i = 0; i < 64; i++)
        this.bytes[i] = 0;
    }

    this.pos = -1;

    return this;
  }

  /**
   * Derive key with XChaCha20.
   * @param {Buffer} key
   * @param {Buffer} nonce
   * @returns {Buffer}
   */

  static derive(key, nonce) {
    assert(Buffer.isBuffer(key));
    assert(Buffer.isBuffer(nonce));

    if (key.length !== 16 && key.length !== 32)
      throw new RangeError('Invalid key size.');

    if (nonce.length !== 16)
      throw new RangeError('Invalid nonce size.');

    const state = new Uint32Array(16);

    state[0] = 0x61707865;
    state[1] = key.length < 32 ? 0x3120646e : 0x3320646e;
    state[2] = key.length < 32 ? 0x79622d36 : 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = readU32(key, 0);
    state[5] = readU32(key, 4);
    state[6] = readU32(key, 8);
    state[7] = readU32(key, 12);
    state[8] = readU32(key, 16 % key.length);
    state[9] = readU32(key, 20 % key.length);
    state[10] = readU32(key, 24 % key.length);
    state[11] = readU32(key, 28 % key.length);
    state[12] = readU32(nonce, 0);
    state[13] = readU32(nonce, 4);
    state[14] = readU32(nonce, 8);
    state[15] = readU32(nonce, 12);

    for (let i = 0; i < 10; i++) {
      qround(state, 0, 4, 8, 12);
      qround(state, 1, 5, 9, 13);
      qround(state, 2, 6, 10, 14);
      qround(state, 3, 7, 11, 15);
      qround(state, 0, 5, 10, 15);
      qround(state, 1, 6, 11, 12);
      qround(state, 2, 7, 8, 13);
      qround(state, 3, 4, 9, 14);
    }

    const out = Buffer.alloc(32);

    writeU32(out, state[0], 0);
    writeU32(out, state[1], 4);
    writeU32(out, state[2], 8);
    writeU32(out, state[3], 12);
    writeU32(out, state[12], 16);
    writeU32(out, state[13], 20);
    writeU32(out, state[14], 24);
    writeU32(out, state[15], 28);

    return out;
  }
}

/*
 * Static
 */

ChaCha20.native = 0;

/*
 * Helpers
 */

function qround(x, a, b, c, d) {
  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 16);

  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 12);

  x[a] += x[b];
  x[d] = rotl32(x[d] ^ x[a], 8);

  x[c] += x[d];
  x[b] = rotl32(x[b] ^ x[c], 7);
}

function rotl32(w, b) {
  return (w << b) | (w >>> (32 - b));
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

function writeU32(dst, num, off) {
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  num >>>= 8;
  dst[off++] = num;
  return off;
}

/*
 * Expose
 */

module.exports = ChaCha20;
}],
[/* 39 */ 'bcrypto', '/lib/sha256-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * sha256.js - sha256 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(20 /* './js/sha256' */);
}],
[/* 40 */ 'bcrypto', '/lib/hmac-drbg-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hmac-drbg.js - hmac-drbg for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(41 /* './js/hmac-drbg' */);
}],
[/* 41 */ 'bcrypto', '/lib/js/hmac-drbg.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * hmac-drbg.js - hmac-drbg implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/hmac-drbg:
 *   Copyright Fedor Indutny, 2017.
 *   https://github.com/indutny/hmac-drbg
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc6979
 *   https://csrc.nist.gov/publications/detail/sp/800-90a/archive/2012-01-23
 *   https://github.com/indutny/hmac-drbg/blob/master/lib/hmac-drbg.js
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);

/*
 * Constants
 */

const RESEED_INTERVAL = 0x1000000000000;
const ZERO = Buffer.from([0x00]);
const ONE = Buffer.from([0x01]);

/**
 * HmacDRBG
 */

class HmacDRBG {
  constructor(hash, entropy, nonce, pers) {
    assert(hash && typeof hash.id === 'string');

    this.hash = hash;
    this.minEntropy = hash.id === 'SHA1' ? 10 : 24;

    this.K = Buffer.alloc(hash.size);
    this.V = Buffer.alloc(hash.size);
    this.rounds = 0;

    if (entropy)
      this.init(entropy, nonce, pers);
  }

  init(entropy, nonce, pers) {
    if (nonce == null)
      nonce = Buffer.alloc(0);

    if (pers == null)
      pers = Buffer.alloc(0);

    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(nonce));
    assert(Buffer.isBuffer(pers));

    for (let i = 0; i < this.V.length; i++) {
      this.K[i] = 0x00;
      this.V[i] = 0x01;
    }

    const seed = Buffer.concat([entropy, nonce, pers]);

    if (seed.length < this.minEntropy)
      throw new Error('Not enough entropy.');

    this.update(seed);
    this.rounds = 1;

    return this;
  }

  reseed(entropy, add) {
    if (add == null)
      add = Buffer.alloc(0);

    assert(Buffer.isBuffer(entropy));
    assert(Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    const seed = Buffer.concat([entropy, add]);

    if (seed.length < this.minEntropy)
     throw new Error('Not enough entropy.');

    this.update(seed);
    this.rounds = 1;

    return this;
  }

  generate(len, add) {
    assert((len >>> 0) === len);
    assert(add == null || Buffer.isBuffer(add));

    if (this.rounds === 0)
      throw new Error('DRBG not initialized.');

    if (this.rounds > RESEED_INTERVAL)
      throw new Error('Reseed is required.');

    if (add && add.length > 0)
      this.update(add);

    const blocks = Math.ceil(len / this.hash.size);
    const out = Buffer.alloc(blocks * this.hash.size);

    for (let i = 0; i < blocks; i++) {
      this.V = this.mac(this.V);
      this.V.copy(out, i * this.hash.size);
    }

    this.update(add);
    this.rounds += 1;

    return out.slice(0, len);
  }

  randomBytes(size) {
    return this.generate(size);
  }

  /*
   * Helpers
   */

  mac(data) {
    return this.hash.mac(data, this.K);
  }

  hmac() {
    return this.hash.hmac().init(this.K);
  }

  update(seed) {
    assert(seed == null || Buffer.isBuffer(seed));

    const kmac = this.hmac();

    kmac.update(this.V);
    kmac.update(ZERO);

    if (seed)
      kmac.update(seed);

    this.K = kmac.final();
    this.V = this.mac(this.V);

    if (seed && seed.length > 0) {
      const kmac = this.hmac();

      kmac.update(this.V);
      kmac.update(ONE);
      kmac.update(seed);

      this.K = kmac.final();
      this.V = this.mac(this.V);
    }

    return this;
  }
}

/*
 * Static
 */

HmacDRBG.native = 0;

/*
 * Expose
 */

module.exports = HmacDRBG;
}],
[/* 42 */ 'bcrypto', '/lib/js/elliptic.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * elliptic.js - elliptic curves for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on indutny/elliptic:
 *   Copyright (c) 2014, Fedor Indutny (MIT License).
 *   https://github.com/indutny/elliptic
 *
 * Formulas from DJB and Tanja Lange [EFD].
 *
 * References:
 *
 *   [GECC] Guide to Elliptic Curve Cryptography
 *     D. Hankerson, A. Menezes, and S. Vanstone
 *     https://tinyurl.com/guide-to-ecc
 *
 *   [GLV] Faster Point Multiplication on Elliptic Curves
 *     R. Gallant, R. Lambert, and S. Vanstone
 *     https://link.springer.com/content/pdf/10.1007/3-540-44647-8_11.pdf
 *
 *   [MONT1] Montgomery curves and the Montgomery ladder
 *     Daniel J. Bernstein, Tanja Lange
 *     https://eprint.iacr.org/2017/293.pdf
 *
 *   [SQUARED] Elligator Squared
 *     Mehdi Tibouchi
 *     https://eprint.iacr.org/2014/043.pdf
 *
 *   [SEC1] SEC 1 - Standards for Efficient Cryptography Group
 *     Certicom Research
 *     https://www.secg.org/sec1-v2.pdf
 *
 *   [SEC2] SEC 2: Recommended Elliptic Curve Domain Parameters
 *     Certicom Research
 *     https://www.secg.org/sec2-v2.pdf
 *
 *   [SIDE1] Elliptic Curves and Side-Channel Attacks
 *     Marc Joye
 *     https://pdfs.semanticscholar.org/8d69/9645033e25d74fcfd4cbf07a770d2e943e14.pdf
 *
 *   [BLIND] Side-Channel Analysis on Blinding Regular Scalar Multiplications
 *     B. Feix, M. Roussellet, A. Venelli
 *     https://eprint.iacr.org/2014/191.pdf
 *
 *   [ALT] Alternative Elliptic Curve Representations
 *     R. Struik
 *     https://tools.ietf.org/id/draft-ietf-lwig-curve-representations-02.html
 *
 *   [ARITH1] Arithmetic of Elliptic Curves
 *     Christophe Doche, Tanja Lange
 *     Handbook of Elliptic and Hyperelliptic Curve Cryptography
 *     Page 267, Section 13 (978-1-58488-518-4)
 *     https://hyperelliptic.org/HEHCC/index.html
 *
 *   [ARITH2] The Arithmetic of Elliptic Curves, 2nd Edition
 *     Joseph H. Silverman
 *     http://www.pdmi.ras.ru/~lowdimma/BSD/Silverman-Arithmetic_of_EC.pdf
 *
 *   [EFD] Explicit-Formulas Database
 *     Daniel J. Bernstein, Tanja Lange
 *     https://hyperelliptic.org/EFD/index.html
 *
 *   [SAFE] SafeCurves: choosing safe curves for elliptic-curve cryptography
 *     Daniel J. Bernstein
 *     https://safecurves.cr.yp.to/
 *
 *   [4GLV] Refinement of the Four-Dimensional GLV Method on Elliptic Curves
 *     Hairong Yi, Yuqing Zhu, and Dongdai Lin
 *     http://www.site.uottawa.ca/~cadams/papers/prepro/paper_19_slides.pdf
 *
 *   [SSWU1] Efficient Indifferentiable Hashing into Ordinary Elliptic Curves
 *     E. Brier, J. Coron, T. Icart, D. Madore, H. Randriam, M. Tibouchi
 *     https://eprint.iacr.org/2009/340.pdf
 *
 *   [SSWU2] Rational points on certain hyperelliptic curves over finite fields
 *     Maciej Ulas
 *     https://arxiv.org/abs/0706.1448
 *
 *   [H2EC] Hashing to Elliptic Curves
 *     A. Faz-Hernandez, S. Scott, N. Sullivan, R. S. Wahby, C. A. Wood
 *     https://git.io/JeWz6
 *     https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
 *
 *   [SVDW1] Construction of Rational Points on Elliptic Curves
 *     A. Shallue, C. E. van de Woestijne
 *     https://works.bepress.com/andrew_shallue/1/download/
 *
 *   [SVDW2] Indifferentiable Hashing to Barreto-Naehrig Curves
 *     Pierre-Alain Fouque, Mehdi Tibouchi
 *     https://www.di.ens.fr/~fouque/pub/latincrypt12.pdf
 *
 *   [SVDW3] Covert ECDH over secp256k1
 *     Pieter Wuille
 *     https://gist.github.com/sipa/29118d3fcfac69f9930d57433316c039
 *
 *   [MONT2] Montgomery Curve (wikipedia)
 *     https://en.wikipedia.org/wiki/Montgomery_curve
 *
 *   [MONT3] Montgomery Curves and their arithmetic
 *     C. Costello, B. Smith
 *     https://eprint.iacr.org/2017/212.pdf
 *
 *   [ELL2] Elliptic-curve points indistinguishable from uniform random strings
 *     D. Bernstein, M. Hamburg, A. Krasnova, T. Lange
 *     https://elligator.cr.yp.to/elligator-20130828.pdf
 *
 *   [RFC7748] Elliptic Curves for Security
 *     A. Langley, M. Hamburg, S. Turner
 *     https://tools.ietf.org/html/rfc7748
 *
 *   [TWISTED] Twisted Edwards Curves
 *     D. Bernstein, P. Birkner, M. Joye, T. Lange, C. Peters
 *     https://eprint.iacr.org/2008/013.pdf
 *
 *   [ELL1] Injective Encodings to Elliptic Curves
 *     P. Fouque, A. Joux, M. Tibouchi
 *     https://eprint.iacr.org/2013/373.pdf
 *
 *   [ISOGENY] Twisting Edwards curves with isogenies
 *     Mike Hamburg
 *     https://www.shiftleft.org/papers/isogeny/isogeny.pdf
 *
 *   [RFC8032] Edwards-Curve Digital Signature Algorithm (EdDSA)
 *     S. Josefsson, SJD AB, I. Liusvaara
 *     https://tools.ietf.org/html/rfc8032
 *
 *   [SCHNORR] Schnorr Signatures for secp256k1
 *     Pieter Wuille
 *     https://github.com/sipa/bips/blob/d194620/bip-schnorr.mediawiki
 *
 *   [BIP340] Schnorr Signatures for secp256k1
 *     Pieter Wuille, Jonas Nick, Tim Ruffing
 *     https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 *
 *   [JCEN12] Efficient Software Implementation of Public-Key Cryptography
 *            on Sensor Networks Using the MSP430X Microcontroller
 *     C. P. L. Gouvea, L. B. Oliveira, J. Lopez
 *     http://conradoplg.cryptoland.net/files/2010/12/jcen12.pdf
 *
 *   [FIPS186] Federal Information Processing Standards Publication
 *     National Institute of Standards and Technology
 *     https://tinyurl.com/fips-186-3
 *
 *   [RFC5639] Elliptic Curve Cryptography (ECC) Brainpool
 *             Standard Curves and Curve Generation
 *     M. Lochter, BSI, J. Merkle
 *     https://tools.ietf.org/html/rfc5639
 *
 *   [TWISTEQ] Twisted Edwards & Short Weierstrass Equivalence
 *     Christopher Jeffrey
 *     https://gist.github.com/chjj/16ba7fa08d64e8dda269a9fe5b2a8bbc
 *
 *   [ECPM] Elliptic Curve Point Multiplication (wikipedia)
 *     https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
 */

'use strict';

const {custom} = __node_require__(33 /* '../internal/custom' */);
const BN = __node_require__(31 /* '../bn' */);

/*
 * Constants
 */

const types = {
  AFFINE: 0,
  JACOBIAN: 1,
  PROJECTIVE: 2,
  EXTENDED: 3
};

const jsfIndex = [
  -3, // -1 -1
  -1, // -1 0
  -5, // -1 1
  -7, // 0 -1
  0, // 0 0
  7, // 0 1
  5, // 1 -1
  1, // 1 0
  3  // 1 1
];

const USE_FIXED = false;

let uid = 0;

/**
 * Curve
 */

class Curve {
  constructor(Point, type, conf) {
    this.Point = null;
    this.id = null;
    this.uid = uid++;
    this.ossl = null;
    this.type = 'base';
    this.endian = 'be';
    this.hash = null;
    this.prefix = null;
    this.context = false;
    this.prime = null;
    this.p = null;
    this.red = null;
    this.fieldSize = 0;
    this.fieldBits = 0;
    this.adjustedSize = 0;
    this.signBit = 0;
    this.mask = 0;
    this.n = null;
    this.h = null;
    this.q = null;
    this.z = null;
    this.g = null;
    this.nh = null;
    this.scalarSize = 0;
    this.scalarBits = 0;
    this.zero = null;
    this.one = null;
    this.two = null;
    this.three = null;
    this.four = null;
    this.i2 = null;
    this.i3 = null;
    this.i4 = null;
    this.i6 = null;
    this.torsion = null;
    this.endo = null;
    this.hi = null;
    this._init(Point, type, conf);
  }

  _init(Point, type, conf) {
    assert(typeof Point === 'function');
    assert(typeof type === 'string');
    assert(conf && typeof conf === 'object');
    assert(conf.red == null || (conf.red instanceof BN.Red));
    assert(conf.p != null, 'Must pass a prime.');
    assert(conf.id == null || typeof conf.id === 'string');
    assert(conf.ossl == null || typeof conf.ossl === 'string');
    assert(conf.endian == null || typeof conf.endian === 'string');
    assert(conf.hash == null || typeof conf.hash === 'string');
    assert(conf.prefix == null || typeof conf.prefix === 'string');
    assert(conf.context == null || typeof conf.context === 'boolean');
    assert(conf.prime == null || typeof conf.prime === 'string');
    assert(conf.torsion == null || Array.isArray(conf.torsion));

    // Point class.
    this.Point = Point;

    // Meta.
    this.id = conf.id || null;
    this.ossl = conf.ossl || null;
    this.type = type;
    this.endian = conf.endian || (type === 'short' ? 'be' : 'le');
    this.hash = conf.hash || null;
    this.prefix = conf.prefix ? Buffer.from(conf.prefix, 'binary') : null;
    this.context = conf.context || false;
    this.prime = conf.prime || null;

    // Prime.
    this.p = BN.fromJSON(conf.p);

    // Reduction.
    if (conf.red) {
      this.red = conf.red;
    } else {
      // Use Montgomery when there is no fast reduction for the prime.
      this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);
      this.red.precompute();
    }

    // Precalculate encoding length.
    this.fieldSize = this.p.byteLength();
    this.fieldBits = this.p.bitLength();
    this.adjustedSize = this.fieldSize + ((this.fieldBits & 7) === 0);
    this.signBit = this.adjustedSize * 8 - 1;
    this.mask = 0xff;

    if ((this.fieldBits & 7) !== 0)
      this.mask = (1 << (this.fieldBits & 7)) - 1;

    // Curve configuration, optional.
    this.n = BN.fromJSON(conf.n || '0');
    this.h = BN.fromJSON(conf.h || '1');
    this.q = this.n.mul(this.h);
    this.z = BN.fromJSON(conf.z || '0').toRed(this.red);
    this.g = null;
    this.nh = this.n.ushrn(1);
    this.scalarSize = this.n.byteLength();
    this.scalarBits = this.n.bitLength();

    // Useful for many curves.
    this.zero = new BN(0).toRed(this.red);
    this.one = new BN(1).toRed(this.red);
    this.two = new BN(2).toRed(this.red);
    this.three = new BN(3).toRed(this.red);
    this.four = new BN(4).toRed(this.red);

    // Inverses.
    this.i2 = this.two.redInvert();
    this.i3 = this.three.redInvert();
    this.i4 = this.i2.redSqr();
    this.i6 = this.i2.redMul(this.i3);

    // Torsion.
    this.torsion = new Array(this.h.word(0));

    for (let i = 0; i < this.torsion.length; i++)
      this.torsion[i] = this.point();

    // Endomorphism.
    this.endo = null;

    // Cache.
    this.hi = null;

    // Memoize.
    this._scale = memoize(this._scale, this);
    this.isIsomorphic = memoize(this.isIsomorphic, this);
    this.isIsogenous = memoize(this.isIsogenous, this);

    // Sanity checks.
    assert(this.p.sign() > 0 && this.p.isOdd());
    assert(this.n.sign() >= 0);
    assert(this.h.sign() > 0 && this.h.cmpn(255) <= 0);
    assert(this.endian === 'be' || this.endian === 'le');

    return this;
  }

  _finalize(conf) {
    assert(conf && typeof conf === 'object');

    // Create base point.
    this.g = conf.g ? this.pointFromJSON(conf.g) : this.point();

    // Parse small order points.
    if (conf.torsion) {
      assert(conf.torsion.length === this.torsion.length);

      for (let i = 0; i < this.torsion.length; i++)
        this.torsion[i] = this.pointFromJSON(conf.torsion[i]);
    }

    return this;
  }

  _findTorsion() {
    // Find all torsion points by grinding.
    assert(!this.n.isZero());

    const h = this.h.word(0);
    const x = this.one.redNeg();
    const out = [this.point()];
    const set = new Set();

    let len = h;

    while (out.length < len) {
      let p;

      x.redIAdd(this.one);

      try {
        p = this.pointFromX(x.clone());
      } catch (e) {
        continue;
      }

      try {
        p = p.mul(this.n);
      } catch (e) {
        len = 2;
        continue;
      }

      if (p.isInfinity())
        continue;

      p.normalize();

      for (const point of [p, p.neg()]) {
        const key = point.key();

        if (!set.has(key)) {
          out.push(point);
          set.add(key);
        }
      }
    }

    out.sort((a, b) => a.cmp(b));

    while (out.length < h)
      out.push(this.point());

    return out;
  }

  _fixedMul(p, k) {
    // Fixed-base method for point multiplication.
    //
    // [ECPM] "Windowed method".
    // [GECC] Page 95, Section 3.3.
    //
    // Windows are appropriately shifted to avoid any
    // doublings. This reduces a 256 bit multiplication
    // down to 64 additions with a window size of 4.
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(p.pre && p.pre.windows);

    // Get precomputed windows.
    const {width, points} = p._getWindows(0, 0);

    // Recompute window size.
    const size = 1 << width;

    // Recompute steps.
    const bits = k.bitLength();
    const steps = ((bits + width - 1) / width) >>> 0;

    // Multiply.
    let acc = this.jpoint();

    for (let i = 0; i < steps; i++) {
      const bits = k.bits(i * width, width);

      acc = acc.add(points[i * size + bits]);
    }

    // Adjust sign.
    if (k.isNeg())
      acc = acc.neg();

    return acc;
  }

  _fixedNafMul(p, k) {
    // Fixed-base NAF windowing method for point multiplication.
    //
    // [GECC] Algorithm 3.42, Page 105, Section 3.3.
    assert(p instanceof Point);
    assert(k instanceof BN);
    assert(p.pre && p.pre.doubles);

    // Get precomputed doubles.
    const {step, points} = p._getDoubles(0, 0);

    // Get fixed NAF (in a more windowed form).
    const naf = getFixedNAF(k, 2, k.bitLength() + 1, step);

    // Compute steps.
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3;

    // Multiply.
    let a = this.jpoint();
    let b = this.jpoint();

    for (let i = I; i > 0; i--) {
      for (let j = 0; j < naf.length; j++) {
        const nafW = naf[j];

        if (nafW === i)
          b = b.add(points[j]);
        else if (nafW === -i)
          b = b.sub(points[j]);
      }

      a = a.add(b);
    }

    return a;
  }

  _wnafMul(w, p, k) {
    // Window NAF method for point multiplication.
    //
    // [GECC] Algorithm 3.36, Page 100, Section 3.3.
    assert(p instanceof Point);
    assert(k instanceof BN);

    // Precompute window.
    const {width, points} = p._safeNAF(w);

    // Get NAF form.
    const naf = getNAF(k, width, k.bitLength() + 1);

    // Add `this`*(N+1) for every w-NAF index.
    let acc = this.jpoint();

    for (let i = naf.length - 1; i >= 0; i--) {
      const z = naf[i];

      if (i !== naf.length - 1)
        acc = acc.dbl();

      if (z > 0)
        acc = acc.add(points[(z - 1) >> 1]);
      else if (z < 0)
        acc = acc.sub(points[(-z - 1) >> 1]);
    }

    return acc;
  }

  _wnafMulAdd(w, points, coeffs) {
    // Multiple point multiplication, also known
    // as "Shamir's trick" (with interleaved NAFs).
    //
    // [GECC] Algorithm 3.48, Page 109, Section 3.3.3.
    //        Algorithm 3.51, Page 112, Section 3.3.
    //
    // This is particularly useful for signature
    // verifications and mutiplications after an
    // endomorphism split.
    assert((w >>> 0) === w);
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);

    const length = points.length;
    const wnd = new Array(length);
    const naf = new Array(length);

    // Check arrays and calculate size.
    let max = 0;

    for (let i = 0; i < length; i++) {
      const point = points[i];
      const coeff = coeffs[i];

      assert(point instanceof Point);
      assert(coeff instanceof BN);

      if (i > 0 && point.type !== points[i - 1].type)
        throw new Error('Cannot mix points.');

      // Avoid sparse arrays.
      wnd[i] = null;
      naf[i] = null;

      // Compute max scalar size.
      max = Math.max(max, coeff.bitLength() + 1);
    }

    // Compute NAFs.
    let ppoint = null;
    let pcoeff = null;
    let len = 0;

    for (let i = 0; i < length; i++) {
      const point = points[i];
      const coeff = coeffs[i];
      const pre = point._getNAF(0);

      // Use precomputation if available.
      if (pre) {
        wnd[len] = pre.points;
        naf[len] = getNAF(coeff, pre.width, max);
        len += 1;
        continue;
      }

      // Save last non-precomputed point.
      if (!ppoint) {
        ppoint = point;
        pcoeff = coeff;
        continue;
      }

      // Compute JSF in NAF form.
      wnd[len] = ppoint._getJNAF(point);
      naf[len] = getJNAF(pcoeff, coeff, max);

      ppoint = null;
      pcoeff = null;

      len += 1;
    }

    // Regular NAF for odd points.
    if (ppoint) {
      const nafw = ppoint._safeNAF(w);

      wnd[len] = nafw.points;
      naf[len] = getNAF(pcoeff, nafw.width, max);

      len += 1;
    }

    // Multiply and add.
    let acc = this.jpoint();

    for (let i = max - 1; i >= 0; i--) {
      if (i !== max - 1)
        acc = acc.dbl();

      for (let j = 0; j < len; j++) {
        const z = naf[j][i];

        if (z > 0)
          acc = acc.add(wnd[j][(z - 1) >> 1]);
        else if (z < 0)
          acc = acc.sub(wnd[j][(-z - 1) >> 1]);
      }
    }

    return acc;
  }

  _endoWnafMulAdd(points, coeffs) {
    throw new Error('Not implemented.');
  }

  _scale(curve, invert) {
    assert(curve instanceof Curve);
    assert(curve.p.eq(this.p));

    switch (curve.type) {
      case 'short':
        return this._scaleShort(curve, invert);
      case 'mont':
        return this._scaleMont(curve, invert);
      case 'edwards':
        return this._scaleEdwards(curve, invert);
      default:
        throw new Error('Not implemented.');
    }
  }

  _scaleShort(curve, invert) {
    throw new Error('Not implemented.');
  }

  _scaleMont(curve, invert) {
    throw new Error('Not implemented.');
  }

  _scaleEdwards(curve, invert) {
    throw new Error('Not implemented.');
  }

  isElliptic() {
    throw new Error('Not implemented.');
  }

  jinv() {
    throw new Error('Not implemented.');
  }

  isComplete() {
    return false;
  }

  precompute(rng) {
    assert(!this.g.isInfinity(), 'Must have base point.');
    assert(!this.n.isZero(), 'Must have order.');

    this.g.precompute(this.n.bitLength(), rng);

    return this;
  }

  scalar(num, base, endian) {
    const k = new BN(num, base, endian);

    assert(!k.red);

    if (this.n.isZero())
      return k;

    return k.imod(this.n);
  }

  field(num, base, endian) {
    const x = BN.cast(num, base, endian);

    if (x.red)
      return x.forceRed(this.red);

    return x.toRed(this.red);
  }

  point(x, y) {
    throw new Error('Not implemented.');
  }

  jpoint(x, y, z) {
    throw new Error('Not implemented.');
  }

  xpoint(x, z) {
    throw new Error('Not implemented.');
  }

  cpoint(xx, xz, yy, yz) {
    assert(xx instanceof BN);
    assert(xz instanceof BN);
    assert(yy instanceof BN);
    assert(yz instanceof BN);

    if (xz.isZero() || yz.isZero())
      return this.point();

    const z = xz.redMul(yz).redInvert();
    const x = xx.redMul(yz).redMul(z);
    const y = yy.redMul(xz).redMul(z);

    return this.point(x, y);
  }

  solveX2(y) {
    throw new Error('Not implemented.');
  }

  solveX(y) {
    return this.solveX2(y).redSqrt();
  }

  solveY2(x) {
    throw new Error('Not implemented.');
  }

  solveY(x) {
    return this.solveY2(x).redSqrt();
  }

  validate(point) {
    throw new Error('Not implemented.');
  }

  pointFromX(x, sign) {
    throw new Error('Not implemented.');
  }

  pointFromY(y, sign) {
    throw new Error('Not implemented.');
  }

  isIsomorphic(curve) {
    throw new Error('Not implemented.');
  }

  isIsogenous(curve) {
    throw new Error('Not implemented.');
  }

  pointFromShort(point) {
    throw new Error('Not implemented.');
  }

  pointFromMont(point, sign) {
    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    throw new Error('Not implemented.');
  }

  pointFromUniform(u) {
    throw new Error('Not implemented.');
  }

  pointToUniform(p) {
    throw new Error('Not implemented.');
  }

  pointFromHash(bytes, pake = false) {
    // [H2EC] "Roadmap".
    assert(Buffer.isBuffer(bytes));
    assert(typeof pake === 'boolean');

    if (bytes.length !== this.fieldSize * 2)
      throw new Error('Invalid hash size.');

    // Random oracle encoding.
    // Ensure a proper distribution.
    const s1 = bytes.slice(0, this.fieldSize);
    const s2 = bytes.slice(this.fieldSize);
    const u1 = this.decodeUniform(s1);
    const u2 = this.decodeUniform(s2);
    const p1 = this.pointFromUniform(u1);
    const p2 = this.pointFromUniform(u2);
    const p3 = p1.add(p2);

    return pake ? p3.mulH() : p3;
  }

  pointToHash(p, subgroup, rng) {
    // [SQUARED] Algorithm 1, Page 8, Section 3.3.
    assert(p instanceof this.Point);
    assert((subgroup >>> 0) === subgroup);

    // Add a random torsion component.
    const i = subgroup % this.torsion.length;
    const p0 = p.add(this.torsion[i]);

    // Average Cost (R = sqrt):
    //
    //   SSWU (~4 iterations) => 8I + 16R
    //   SVDW (~4 iterations) => 12I + 28R
    //   Elligator 1 (~2 iterations) => 6I + 10R
    //   Elligator 2 (~2 iterations) => 4I + 6R
    //   Ristretto (~1 iteration) => 1I + 2R + h*1R
    for (;;) {
      const u1 = this.randomField(rng);
      const p1 = this.pointFromUniform(u1);

      // Avoid 2-torsion points:
      //   Short Weierstrass: ((A / 3) / B, 0)
      //   Montgomery: (0, 0)
      //   Twisted Edwards: (0, -1)
      if (p1.neg().eq(p1))
        continue;

      const p2 = p0.sub(p1);
      const hint = randomInt(rng);

      let u2;
      try {
        u2 = this.pointToUniform(p2, hint & 15);
      } catch (e) {
        if (e.message === 'Invalid point.')
          continue;
        throw e;
      }

      const s1 = this.encodeUniform(u1, hint >>> 8);
      const s2 = this.encodeUniform(u2, hint >>> 16);

      return Buffer.concat([s1, s2]);
    }
  }

  randomScalar(rng) {
    const max = this.n.isZero() ? this.p : this.n;
    return BN.random(rng, 1, max);
  }

  randomField(rng) {
    return BN.random(rng, 1, this.p).toRed(this.red);
  }

  randomPoint(rng) {
    let p;

    for (;;) {
      const x = this.randomField(rng);
      const sign = (randomInt(rng) & 1) !== 0;

      try {
        p = this.pointFromX(x, sign);
      } catch (e) {
        continue;
      }

      assert(p.validate());

      return p.mulH();
    }
  }

  mulAll(points, coeffs) {
    return this.jmulAll(points, coeffs);
  }

  jmulAll(points, coeffs) {
    assert(Array.isArray(points));
    assert(points.length === 0 || (points[0] instanceof Point));

    // Multiply with endomorphism if we're using affine points.
    if (this.endo && points.length > 0 && points[0].type === types.AFFINE)
      return this._endoWnafMulAdd(points, coeffs);

    // Otherwise, a regular Shamir's trick.
    return this._wnafMulAdd(5, points, coeffs);
  }

  mulH(k) {
    assert(k instanceof BN);
    return this.imulH(k.clone());
  }

  imulH(k) {
    assert(k instanceof BN);
    assert(!k.red);

    const word = this.h.word(0);

    // Optimize for powers of two.
    if ((word & (word - 1)) === 0) {
      const bits = this.h.bitLength();
      return k.iushln(bits - 1).imod(this.n);
    }

    return k.imuln(word).imod(this.n);
  }

  normalizeAll(points) {
    assert(Array.isArray(points));

    const len = points.length;
    const z = new Array(len);

    for (let i = 0; i < len; i++) {
      const p = points[i];

      assert(p instanceof Point);
      assert(p.curve === this);

      if (p.type === types.AFFINE) {
        z[i] = this.one;
        continue;
      }

      z[i] = p.z;
    }

    const zi = this.red.invertAll(z);
    const out = new Array(len);

    for (let i = 0; i < len; i++)
      out[i] = points[i].scale(zi[i]);

    return out;
  }

  affinizeAll(points) {
    return this.normalizeAll(points);
  }

  clamp(scalar) {
    // [RFC7748] Page 8, Section 5.
    // [RFC8032] Section 5.1.5 & 5.2.5.
    assert(Buffer.isBuffer(scalar));
    assert(scalar.length === this.scalarSize);
    assert(this.scalarSize <= this.fieldSize);

    let top = (this.fieldBits & 7) || 8;
    let lsb = 0;
    let msb = this.scalarSize - 1;

    // Swap endianness.
    if (this.endian === 'be')
      [lsb, msb] = [msb, lsb];

    // Adjust for low order.
    if (this.scalarSize < this.fieldSize)
      top = 8;

    // Ensure a multiple of the cofactor.
    scalar[lsb] &= -this.h.word(0) & 0xff;

    // Clamp to the prime.
    scalar[msb] &= (1 << top) - 1;

    // Set the high bit.
    scalar[msb] |= 1 << (top - 1);

    return scalar;
  }

  splitHash(bytes) {
    // [RFC8032] Section 5.1.6 & 5.2.6.
    assert(Buffer.isBuffer(bytes));
    assert(bytes.length === this.adjustedSize * 2);
    assert(this.scalarSize <= this.adjustedSize);

    let off = 0;

    if (this.endian === 'be')
      off = this.adjustedSize - this.scalarSize;

    const scalar = bytes.slice(off, off + this.scalarSize);
    const prefix = bytes.slice(this.adjustedSize);

    this.clamp(scalar);

    return [scalar, prefix];
  }

  encodeField(x) {
    // [SEC1] Page 12, Section 2.3.5.
    assert(x instanceof BN);
    assert(!x.red);

    return x.encode(this.endian, this.fieldSize);
  }

  decodeField(bytes) {
    // [SEC1] Page 13, Section 2.3.6.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field element size.');

    return BN.decode(bytes, this.endian);
  }

  encodeAdjusted(x) {
    assert(x instanceof BN);
    assert(!x.red);

    return x.encode(this.endian, this.adjustedSize);
  }

  decodeAdjusted(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.adjustedSize)
      throw new Error('Invalid field element size.');

    return BN.decode(bytes, this.endian);
  }

  encodeScalar(k) {
    // [SEC1] Page 13, Section 2.3.7.
    assert(k instanceof BN);
    assert(!k.red);

    return k.encode(this.endian, this.scalarSize);
  }

  decodeScalar(bytes) {
    // [SEC1] Page 14, Section 2.3.8.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarSize)
      throw new Error('Invalid scalar size.');

    return BN.decode(bytes, this.endian);
  }

  encodeClamped(k) {
    // [RFC7748] Page 8, Section 5.
    // [RFC8032] Section 5.1.5 & 5.2.5.
    return this.clamp(this.encodeScalar(k));
  }

  decodeClamped(bytes) {
    // [RFC7748] Page 8, Section 5.
    // [RFC8032] Section 5.1.5 & 5.2.5.
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.scalarSize)
      throw new Error('Invalid scalar size.');

    const clamped = this.clamp(Buffer.from(bytes));

    return BN.decode(clamped, this.endian);
  }

  encodeUniform(x, bits) {
    assert(x instanceof BN);
    assert((bits >>> 0) === bits);

    const msb = this.endian === 'le' ? this.fieldSize - 1 : 0;
    const bytes = x.fromRed().encode(this.endian, this.fieldSize);

    bytes[msb] |= (bits & ~this.mask) & 0xff;

    return bytes;
  }

  decodeUniform(bytes) {
    assert(Buffer.isBuffer(bytes));

    if (bytes.length !== this.fieldSize)
      throw new Error('Invalid field size.');

    const x = BN.decode(bytes, this.endian);

    x.iumaskn(this.fieldBits);

    return x.toRed(this.red);
  }

  encodePoint(point, compact) {
    assert(point instanceof Point);
    return point.encode(compact);
  }

  decodePoint(bytes) {
    throw new Error('Not implemented.');
  }

  encodeX(point) {
    throw new Error('Not implemented.');
  }

  decodeX(bytes) {
    throw new Error('Not implemented.');
  }

  decodeEven(bytes) {
    throw new Error('Not implemented.');
  }

  decodeSquare(bytes) {
    throw new Error('Not implemented.');
  }

  toShort() {
    throw new Error('Not implemented.');
  }

  toMont(b0) {
    throw new Error('Not implemented.');
  }

  toEdwards(a0) {
    throw new Error('Not implemented.');
  }

  pointToJSON(point, pre) {
    assert(point instanceof Point);
    return point.toJSON(pre);
  }

  pointFromJSON(json) {
    throw new Error('Not implemented.');
  }

  toJSON(pre) {
    let prefix, context;
    let n, z, endo;

    if (this.type === 'edwards') {
      prefix = this.prefix ? this.prefix.toString() : null;
      context = this.context;
    }

    if (!this.n.isZero())
      n = this.n.toJSON();

    if (!this.z.isZero()) {
      z = this.z.fromRed();

      if (this.z.redIsHigh())
        z.isub(this.p);

      z = z.toString(16);
    }

    if (this.endo)
      endo = this.endo.toJSON();

    return {
      id: this.id,
      ossl: this.ossl,
      type: this.type,
      endian: this.endian,
      hash: this.hash,
      prefix,
      context,
      prime: this.prime,
      p: this.p.toJSON(),
      a: undefined,
      b: undefined,
      d: undefined,
      n,
      h: this.h.toString(16),
      s: undefined,
      z,
      c: undefined,
      g: this.g.toJSON(pre),
      endo
    };
  }

  static fromJSON(json) {
    return new this(json);
  }
}

/**
 * Point
 */

class Point {
  constructor(curve, type) {
    assert(curve instanceof Curve);
    assert((type >>> 0) === type);

    this.curve = curve;
    this.type = type;
    this.pre = null;
  }

  _init() {
    throw new Error('Not implemented.');
  }

  _safeNAF(width) {
    assert((width >>> 0) === width);

    if (this.pre && this.pre.naf)
      return this.pre.naf;

    if (width === 0)
      return null;

    const size = 1 << (width - 2);
    const points = new Array(size);
    const p = this.toJ();
    const dbl = size === 1 ? null : p.dbl();

    points[0] = p;

    for (let i = 1; i < size; i++)
      points[i] = points[i - 1].add(dbl);

    return new NAF(width, points);
  }

  _getNAF(width) {
    assert((width >>> 0) === width);

    if (this.pre && this.pre.naf)
      return this.pre.naf;

    if (width === 0)
      return null;

    const odds = this._safeNAF(width).points;
    const points = this.curve.affinizeAll(odds);

    return new NAF(width, points);
  }

  _getWindows(width, bits) {
    assert((width >>> 0) === width);
    assert((bits >>> 0) === bits);

    if (this.pre && this.pre.windows)
      return this.pre.windows;

    if (width === 0)
      return null;

    const size = 1 << width;
    const steps = ((bits + width - 1) / width) >>> 0;
    const wnds = new Array(steps * size);

    let g = this.toJ();

    for (let i = 0; i < steps; i++) {
      wnds[i * size] = this.curve.jpoint();

      for (let j = 1; j < size; j++)
        wnds[i * size + j] = wnds[i * size + j - 1].add(g);

      g = g.dblp(width);
    }

    const points = this.curve.affinizeAll(wnds);

    return new Windows(width, bits, points);
  }

  _getDoubles(step, power) {
    assert((step >>> 0) === step);
    assert((power >>> 0) === power);

    if (this.pre && this.pre.doubles)
      return this.pre.doubles;

    if (step === 0)
      return null;

    const len = Math.ceil(power / step) + 1;
    const dbls = new Array(len);

    let acc = this.toJ();
    let k = 0;

    dbls[k++] = acc;

    for (let i = 0; i < power; i += step) {
      for (let j = 0; j < step; j++)
        acc = acc.dbl();

      dbls[k++] = acc;
    }

    assert(k === len);

    const points = this.curve.affinizeAll(dbls);

    return new Doubles(step, points);
  }

  _getBeta() {
    return null;
  }

  _getBlinding(rng) {
    if (this.pre && this.pre.blinding)
      return this.pre.blinding;

    if (!rng)
      return null;

    if (this.curve.n.isZero())
      return null;

    // Pregenerate a random blinding value:
    //
    //   blind = random integer in [1,n-1]
    //   unblind = G * blind
    //
    // We intend to subtract the blinding value
    // from scalars before multiplication. We
    // can add the unblinding point once the
    // multiplication is complete.
    const blind = this.curve.randomScalar(rng);
    const unblind = this.mul(blind);

    return new Blinding(blind, unblind);
  }

  _hasWindows(k) {
    assert(k instanceof BN);

    if (!this.pre || !this.pre.windows)
      return false;

    const {width, bits} = this.pre.windows;
    const steps = ((bits + width - 1) / width) >>> 0;

    return k.bitLength() <= steps * width;
  }

  _hasDoubles(k) {
    assert(k instanceof BN);

    if (!this.pre || !this.pre.doubles)
      return false;

    const {step, points} = this.pre.doubles;
    const power = k.bitLength() + 1;

    return points.length >= Math.ceil(power / step) + 1;
  }

  _getJNAF(point) {
    assert(point instanceof Point);
    assert(point.type === this.type);

    // Create comb for JSF.
    return [
      this, // 1
      this.add(point), // 3
      this.sub(point), // 5
      point // 7
    ];
  }

  _blind(k, rng) {
    // [SIDE1] Page 5, Section 4.
    // [BLIND] Page 20, Section 7.
    assert(k instanceof BN);
    assert(!k.red);

    // Scalar splitting (requires precomputation).
    //
    // Blind a multiplication by first subtracting
    // a blinding value from the scalar. Example:
    //
    //   b = random integer in [1,n-1]
    //   B = P * b (precomputed)
    //   Q = P * (k - b) + B
    //
    // Note that Joye describes a different method
    // (multiplier randomization) which computes:
    //
    //   B = random point in E
    //   Q = (P + B) * k - B * k
    //
    // Our method is more similar to the "scalar
    // splitting" technique described in the
    // second source above.
    //
    // The blinding value and its corresponding
    // point are randomly generated and computed
    // on boot. As long as an attacker is not
    // able to observe the boot, this should give
    // a decent bit of protection against various
    // channel attacks.
    if (this.pre && this.pre.blinding) {
      const {blind, unblind} = this.pre.blinding;
      const t = k.sub(blind);

      return [this, t, unblind];
    }

    // Randomization is not possible without
    // an RNG. Do a normal multiplication.
    if (!rng)
      return [this, k, null];

    // If we have no precomputed blinding
    // factor, there are two possibilities
    // for randomization:
    //
    // 1. Randomize the multiplier by adding
    //    a random multiple of `n`.
    //
    // 2. Re-scale the point itself by a
    //    random factor.
    //
    // The first option can be accomplished
    // with some like:
    //
    //   a = random integer in [1,n-1]
    //   r = a * n
    //   Q = P * (k + r)
    //
    // The second is accomplished with:
    //
    //   a = random element in F(p)
    //   R = (x * a^2, y * a^3, z * a)
    //   Q = R * k
    //
    // If we have precomputed doubles / naf
    // points, we opt for the first method
    // to avoid randomizing everything.
    if (this.pre) {
      if (this.curve.n.isZero())
        return [this, k, null];

      const a = this.curve.randomScalar(rng);
      const r = a.mul(this.curve.n);
      const t = r.iadd(k);

      return [this, t, null];
    }

    // If there is no precomputation _at all_,
    // we opt for the second method.
    const p = this.randomize(rng);

    return [p, k, null];
  }

  clone() {
    throw new Error('Not implemented.');
  }

  precompute(bits, rng) {
    assert((bits >>> 0) === bits);

    if (!this.pre)
      this.pre = new Precomp();

    if (!this.pre.naf)
      this.pre.naf = this._getNAF(9);

    if (USE_FIXED && !this.pre.windows)
      this.pre.windows = this._getWindows(4, bits);

    if (!this.pre.doubles)
      this.pre.doubles = this._getDoubles(4, bits + 1);

    if (!this.pre.beta)
      this.pre.beta = this._getBeta();

    if (!this.pre.blinding)
      this.pre.blinding = this._getBlinding(rng);

    return this;
  }

  validate() {
    return this.curve.validate(this);
  }

  normalize() {
    return this;
  }

  scale(a) {
    throw new Error('Not implemented.');
  }

  randomize(rng) {
    const z = this.curve.randomField(rng);
    return this.scale(z);
  }

  neg() {
    throw new Error('Not implemented.');
  }

  add(point) {
    throw new Error('Not implemented.');
  }

  sub(point) {
    assert(point instanceof Point);
    return this.add(point.neg());
  }

  dbl() {
    throw new Error('Not implemented.');
  }

  dblp(pow) {
    // Repeated doubling. This can
    // be optimized by child classes.
    assert((pow >>> 0) === pow);

    let r = this;

    for (let i = 0; i < pow; i++)
      r = r.dbl();

    return r;
  }

  diffAddDbl(p, q) {
    throw new Error('Not implemented.');
  }

  getX() {
    throw new Error('Not implemented.');
  }

  getY() {
    throw new Error('Not implemented.');
  }

  eq(point) {
    throw new Error('Not implemented.');
  }

  cmp(point) {
    throw new Error('Not implemented.');
  }

  isInfinity() {
    throw new Error('Not implemented.');
  }

  isOrder2() {
    throw new Error('Not implemented.');
  }

  isOdd() {
    throw new Error('Not implemented.');
  }

  isEven() {
    throw new Error('Not implemented.');
  }

  isSquare() {
    throw new Error('Not implemented.');
  }

  eqX(x) {
    throw new Error('Not implemented.');
  }

  eqR(x) {
    throw new Error('Not implemented.');
  }

  isSmall() {
    // Test whether the point is of small order.
    if (this.isInfinity())
      return false;

    // P * h = O
    return this.jmulH().isInfinity();
  }

  hasTorsion() {
    // Test whether the point is in another subgroup.
    if (this.isInfinity())
      return false;

    // P * n != O
    return !this.jmul(this.curve.n).isInfinity();
  }

  order() {
    // Calculate point order.
    const {h, n} = this.curve;

    let p = this.toJ();
    let q = new BN(1);

    while (!p.isInfinity()) {
      q.iaddn(1);

      if (q.cmp(h) > 0) {
        q = n.clone();
        break;
      }

      p = p.add(this);
    }

    return q;
  }

  mul(k) {
    return this.jmul(k);
  }

  muln(k) {
    return this.jmuln(k);
  }

  mulBlind(k, rng) {
    return this.jmulBlind(k, rng);
  }

  mulAdd(k1, p2, k2) {
    return this.jmulAdd(k1, p2, k2);
  }

  mulH() {
    return this.jmulH();
  }

  div(k) {
    return this.jdiv(k);
  }

  divn(k) {
    return this.jdivn(k);
  }

  divH() {
    return this.jdivH();
  }

  jmul(k) {
    if (USE_FIXED && this._hasWindows(k))
      return this.curve._fixedMul(this, k);

    if (this._hasDoubles(k))
      return this.curve._fixedNafMul(this, k);

    if (this.curve.endo && this.type === types.AFFINE)
      return this.curve._endoWnafMulAdd([this], [k]);

    return this.curve._wnafMul(5, this, k);
  }

  jmuln(k) {
    assert((k | 0) === k);
    return this.jmul(new BN(k));
  }

  jmulBlind(k, rng = null) {
    const [p, t, unblind] = this._blind(k, rng);
    const q = p.jmul(t);

    if (unblind)
      return q.add(unblind);

    return q;
  }

  jmulAdd(k1, p2, k2) {
    if (this.curve.endo && this.type === types.AFFINE)
      return this.curve._endoWnafMulAdd([this, p2], [k1, k2]);

    return this.curve._wnafMulAdd(5, [this, p2], [k1, k2]);
  }

  jmulH() {
    const word = this.curve.h.word(0);

    // Optimize for powers of two.
    if ((word & (word - 1)) === 0) {
      const bits = this.curve.h.bitLength();
      return this.toJ().dblp(bits - 1);
    }

    return this.jmul(this.curve.h);
  }

  jdiv(k) {
    assert(k instanceof BN);
    assert(!k.red);

    return this.jmul(k.invert(this.curve.n));
  }

  jdivn(k) {
    assert(!this.curve.n.isZero());

    if (this.curve.h.cmpn(k) === 0)
      return this.jdivH();

    return this.jdiv(new BN(k));
  }

  jdivH() {
    if (this.curve.n.isZero())
      return this.toJ();

    if (this.curve.h.cmpn(1) === 0)
      return this.toJ();

    if (this.curve.hi === null)
      this.curve.hi = this.curve.h.invert(this.curve.n);

    return this.jmul(this.curve.hi);
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  toX() {
    return this;
  }

  key() {
    if (this.isInfinity())
      return `${this.curve.uid}:oo`;

    this.normalize();

    const x = this.getX().toString(16);
    const y = this.getY().toString(16);

    return `${this.curve.uid}:${x},${y}`;
  }

  encode(compact) {
    throw new Error('Not implemented.');
  }

  static decode(curve, bytes) {
    throw new Error('Not implemented.');
  }

  encodeX() {
    throw new Error('Not implemented.');
  }

  static decodeX(curve, bytes) {
    throw new Error('Not implemented.');
  }

  static decodeEven(curve, bytes) {
    throw new Error('Not implemented.');
  }

  static decodeSquare(curve, bytes) {
    throw new Error('Not implemented.');
  }

  toJSON(pre) {
    throw new Error('Not implemented.');
  }

  static fromJSON(curve, json) {
    throw new Error('Not implemented.');
  }

  [custom]() {
    return '<Point>';
  }
}

/**
 * ShortCurve
 */

class ShortCurve extends Curve {
  constructor(conf) {
    super(ShortPoint, 'short', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.b = BN.fromJSON(conf.b).toRed(this.red);
    this.c = BN.fromJSON(conf.c || '0').toRed(this.red);
    this.ai = this.a.isZero() ? this.zero : this.a.redInvert();
    this.zi = this.z.isZero() ? this.zero : this.z.redInvert();

    this.zeroA = this.a.isZero();
    this.threeA = this.a.eq(this.three.redNeg());
    this.redN = this.n.toRed(this.red);
    this.pmodn = this.p.clone();
    this.highOrder = this.n.cmp(this.p) >= 0;
    this.smallGap = false;

    this._finalize(conf);
  }

  _finalize(conf) {
    super._finalize(conf);

    // Precalculate endomorphism.
    if (conf.endo != null)
      this.endo = Endo.fromJSON(this, conf.endo);
    else
      this.endo = this._getEndomorphism();

    if (!this.n.isZero()) {
      this.pmodn = this.p.mod(this.n);

      // Check for Maxwell's trick (see eqR).
      this.smallGap = this.p.div(this.n).cmpn(1) <= 0;
    }

    return this;
  }

  static _isomorphism(curveA, curveB, custom, odd) {
    // Short Weierstrass Isomorphism.
    //
    // [GECC] Page 84, Section 3.1.5.
    // [ARITH1] Page 274, Section 13.1.5.
    // [ALT] Appendix F.3 (Isomorphic Mapping between Weierstrass Curves).
    //
    // Find `u` such that `a * u^4 = a'` and `b * u^6 = b'`.
    //
    // Transformation:
    //
    //   u4 = a' / a
    //   u2 = +-sqrt(u4)
    //   u6 = u4 * u2
    //   a' = a * u4
    //   b' = b * u6
    //
    // Where `u2` is any root that is square.
    //
    // If a = 0, we can do:
    //
    //   a' = 0
    //   b' = b'
    //
    // Where (b' / b)^(1 / 3) is square.
    //
    // If b = 0, we can do:
    //
    //   a' = a'
    //   b' = 0
    //
    // Where sqrt(a' / a) is square.
    assert(curveA instanceof BN);
    assert(curveB instanceof BN);
    assert(custom instanceof BN);
    assert(odd == null || typeof odd === 'boolean');
    assert(!curveA.isZero() || !curveB.isZero());

    if (custom.isZero())
      throw new Error('Invalid coefficient.');

    if (curveA.isZero()) {
      const customB = custom;
      const u6 = customB.redDiv(curveB);
      // Todo: allow index flag.
      const u2 = uncube(u6);

      // Already checked in uncube().
      assert(u2.redJacobi() === 1);

      return [curveA.clone(), customB.clone()];
    }

    if (curveB.isZero()) {
      const customA = custom;
      const u4 = customA.redDiv(curveA);
      const u2 = u4.redSqrt();

      // Todo: allow odd flag.
      if (u2.redJacobi() !== 1)
        u2.redINeg();

      if (u2.redJacobi() !== 1)
        throw new Error('Invalid `a` coefficient.');

      return [customA.clone(), curveB.clone()];
    }

    const customA = custom;
    const u4 = customA.redDiv(curveA);
    const u2 = u4.redSqrt();

    if (odd != null) {
      if (u2.redIsOdd() !== odd)
        u2.redINeg();
    } else {
      if (u2.redJacobi() !== 1)
        u2.redINeg();
    }

    if (u2.redJacobi() !== 1)
      throw new Error('Invalid `a` coefficient.');

    const u6 = u4.redMul(u2);
    const a = curveA.redMul(u4);
    const b = curveB.redMul(u6);

    assert(a.eq(customA));

    return [a, b];
  }

  _short(a0, odd) {
    return ShortCurve._isomorphism(this.a, this.b, a0, odd);
  }

  _mont(b0, odd) {
    // Short Weierstrass->Montgomery Equivalence.
    //
    // [ARITH1] Page 286, Section 13.2.3.c.
    // [SAFE] "Ladders".
    //
    // Transformation:
    //
    //   r = A / (3 * B)
    //   s = +-sqrt(3 * r^2 + a)
    //   A = 3 * r / s
    //   B = 1 / s
    const [r, s] = this._findRS(odd);
    const b = s.redInvert();
    const a = r.redMuln(3).redMul(b);

    if (b0 != null)
      return MontCurve._isomorphism(a, b, b0);

    return [a, b];
  }

  _edwards(a0, odd) {
    // Short Weierstrass->Twisted Edwards Equivalence.
    //
    // [TWISTEQ] Section 1.
    //
    // Transformation:
    //
    //   r = (a' + d') / 6
    //   s = +-sqrt(3 * r^2 + a)
    //   a' = 3 * r + 2 * s
    //   d' = 3 * r - 2 * s
    const [r, s] = this._findRS(odd);
    const r3 = r.redMuln(3);
    const s2 = s.redMuln(2);
    const a = r3.redAdd(s2);
    const d = r3.redSub(s2);

    if (a0 != null)
      return EdwardsCurve._isomorphism(a, d, a0);

    return [a, d];
  }

  _findRS(sign) {
    // Find `r` and `s` for equivalence.
    //
    // [ARITH1] Page 286, Section 13.2.3.c.
    // [SAFE] "Ladders".
    //
    // Computation:
    //
    //   r = solve(r^3 + a * r + b == 0, r)
    //   s = +-sqrt(3 * r^2 + a)
    //
    // Computing `r` is non-trivial. We need
    // to solve `r^3 + a * r + b = 0`, but we
    // don't have a polynomial solver, so we
    // loop over random points until we find
    // one with 2-torsion. Multiplying by the
    // subgroup order should yield a point of
    // ((A / 3) / B, 0) which is a solution.
    assert(sign == null || typeof sign === 'boolean');
    assert(this.h.word(0) >= 4);
    assert(!this.n.isZero());

    const x = this.one.redNeg();

    let p;

    for (;;) {
      x.redIAdd(this.one);

      try {
        p = this.pointFromX(x.clone());
      } catch (e) {
        continue;
      }

      p = p.mul(this.n);

      if (p.isInfinity())
        continue;

      if (!p.y.isZero())
        continue;

      break;
    }

    const r = p.x;
    const r2 = r.redSqr();
    const s = r2.redMuln(3).redIAdd(this.a).redSqrt();

    if (sign != null) {
      if (s.redIsOdd() !== sign)
        s.redINeg();
    }

    return [r, s];
  }

  _scale0(a, b) {
    // We can extract the isomorphism factors with:
    //
    //   u4 = a' / a
    //   u6 = b' / b
    //   u2 = +-sqrt(u4)
    //   u = +-sqrt(u2)
    //   u3 = u2 * u
    //
    // `u2` should be picked such that `u4 * u2 = u6`.
    //
    // If a = 0, we can do:
    //
    //   u6 = b' / b
    //   u2 = u6^(1 / 3)
    //   u = +-sqrt(u2)
    //   u3 = u2 * u
    //
    // Where `u2` is any root that is square.
    //
    // If b = 0, we can do:
    //
    //   u4 = a' / a
    //   u2 = +-sqrt(u4)
    //   u = +-sqrt(u2)
    //   u3 = u2 * u
    //
    // Where `u2` is any root that is square.
    assert(this.a.isZero() === a.isZero());
    assert(this.b.isZero() === b.isZero());

    if (this.a.isZero()) {
      const u6 = this.b.redDiv(this.field(b));
      // Todo: figure out how to check index.
      const u2 = uncube(u6);
      const u = u2.redSqrt();
      const u3 = u2.redMul(u);

      assert(u3.redSqr().eq(u6));
      assert(!u.isZero());

      return [u2, u3];
    }

    if (this.b.isZero()) {
      const u4 = this.a.redDiv(this.field(a));
      const u2 = u4.redSqrt();

      // Todo: figure out how to check oddness.
      if (u2.redJacobi() !== 1)
        u2.redINeg();

      const u = u2.redSqrt();
      const u3 = u2.redMul(u);

      assert(u3.redMul(u).eq(u4));
      assert(!u.isZero());

      return [u2, u3];
    }

    const u4 = this.a.redDiv(this.field(a));
    const u6 = this.b.redDiv(this.field(b));
    const u2 = u4.redSqrt();

    if (!u4.redMul(u2).eq(u6))
      u2.redINeg();

    assert(u4.redMul(u2).eq(u6));

    const u = u2.redSqrt();
    const u3 = u2.redMul(u);

    assert(!u.isZero());

    return [u2, u3];
  }

  _scale1(x, y) {
    // If base points are available, it is much
    // easier, with:
    //
    //   u2 = x' / x
    //   u3 = y' / y
    //   u = +-sqrt(u2)
    //
    // `u` should be picked such that `u2 * u = u3`.
    const u2 = this.g.x.redDiv(this.field(x));
    const u3 = this.g.y.redDiv(this.field(y));
    const u = u2.redSqrt();

    if (!u2.redMul(u).eq(u3))
      u.redINeg();

    assert(u2.redMul(u).eq(u3));
    assert(!u.isZero());

    return [u2, u3];
  }

  _scaleShort(curve) {
    assert(curve instanceof ShortCurve);

    if (this.g.isInfinity() || curve.g.isInfinity())
      return this._scale0(curve.a, curve.b);

    return this._scale1(curve.g.x, curve.g.y);
  }

  _scaleMont(curve) {
    assert(curve instanceof MontCurve);

    if (this.g.isInfinity() || curve.g.isInfinity()) {
      const [a, b] = curve._short();
      return this._scale0(a, b);
    }

    const {x, y} = curve.g;
    const nx = x.redAdd(curve.a3).redMul(curve.bi);
    const ny = y.redMul(curve.bi);

    return this._scale1(nx, ny);
  }

  _scaleEdwards(curve) {
    assert(curve instanceof EdwardsCurve);

    if (this.g.isInfinity() || curve.g.isInfinity()) {
      const [a, b] = curve._short();
      return this._scale0(a, b);
    }

    const {x, y, z} = curve.g;
    const a5 = curve.a.redMuln(5);
    const d5 = curve.d.redMuln(5);
    const dma = curve.d.redSub(curve.a);
    const d5a = d5.redSub(curve.a);
    const da5 = curve.d.redSub(a5);
    const ypz = y.redAdd(z);
    const ymz = y.redSub(z);
    const xx = d5a.redMul(y).redIAdd(da5.redMul(z));
    const xz = ymz.redMuln(12);
    const yy = dma.redMul(ypz).redMul(z);
    const yz = ymz.redMul(x).redIMuln(4);
    const zi = xz.redMul(yz).redInvert();
    const nx = xx.redMul(yz).redMul(zi);
    const ny = yy.redMul(xz).redMul(zi);

    return this._scale1(nx, ny);
  }

  _getEndomorphism(index = 0) {
    // Compute endomorphism.
    //
    // [GECC] Example 3.76, Page 128, Section 3.5.

    // No curve params.
    if (this.n.isZero() || this.g.isInfinity())
      return null;

    // No efficient endomorphism.
    if (!this.zeroA || this.p.modrn(3) !== 1 || this.n.modrn(3) !== 1)
      return null;

    // Solve beta^3 mod p = 1.
    const [b1, b2] = this._getEndoRoots(this.p);

    // Choose the smallest beta by default.
    const beta = [b1, b2][index & 1].toRed(this.red);

    // Solve lambda^3 mod n = 1.
    const [l1, l2] = this._getEndoRoots(this.n);

    // Choose the lambda matching selected beta.
    // Note that P * lambda = (x * beta, y).
    const p = this.point(this.g.x.redMul(beta), this.g.y);

    let lambda;

    if (this.g.mul(l1).eq(p)) {
      lambda = l1;
    } else {
      assert(this.g.mul(l2).eq(p));
      lambda = l2;
    }

    // Get basis vectors.
    const basis = this._getEndoBasis(lambda);

    // Precompute `g1` and `g2`.
    const pre = this._getEndoPrecomp(basis);

    return new Endo(beta, lambda, basis, pre);
  }

  _getEndoRoots(num) {
    // Find roots for x^2 + x + 1 in F.
    //
    // [GECC] Example 3.76, Page 128, Section 3.5.
    // [GLV] Page 192, Section 2 (Endomorphisms).
    //
    // The above document doesn't fully explain how
    // to derive these and only "hints" at it, as
    // mentioned by Hal Finney[1], but we're basically
    // computing two possible cube roots of 1 here.
    //
    // Note that we could also compute[2]:
    //
    //   beta = 2^((p - 1) / 3) mod p
    //   lambda = 3^((n - 1) / 3) mod n
    //
    // As an extension of Fermat's little theorem:
    //
    //   g^(p - 1) mod p == 1
    //
    // It is suspected[3] this is how Hal Finney[4]
    // computed his original endomorphism roots.
    //
    // @indutny's method for computing cube roots
    // of unity[5] appears to be the method described
    // on wikipedia[6][7].
    //
    // Sage produces the same solution:
    //
    //   sage: solve(x^2 + x + 1 == 0, x)
    //   [x == -1/2*I*sqrt(3) - 1/2, x == 1/2*I*sqrt(3) - 1/2]
    //
    // This can be reduced to:
    //
    //   x = (+-sqrt(-3) - 1) / 2
    //
    // [1] https://bitcointalk.org/index.php?topic=3238.msg45565#msg45565
    // [2] https://crypto.stackexchange.com/a/22739
    // [3] https://bitcoin.stackexchange.com/a/35872
    // [4] https://github.com/halfinney/bitcoin/commit/dc411b5
    // [5] https://en.wikipedia.org/wiki/Cube_root_of_unity
    // [6] https://en.wikipedia.org/wiki/Splitting_field#Cubic_example
    // [7] http://mathworld.wolfram.com/SplittingField.html
    const red = num === this.p ? this.red : BN.mont(num);
    const two = new BN(2).toRed(red);
    const three = new BN(3).toRed(red);
    const i2 = two.redInvert();

    // S1 = sqrt(-3) / 2
    const s1 = three.redNeg().redSqrt().redMul(i2);

    // S2 = -S1
    const s2 = s1.redNeg();

    // R1 = S1 - 1 / 2
    const r1 = s1.redSub(i2).fromRed();

    // R2 = S2 - 1 / 2
    const r2 = s2.redSub(i2).fromRed();

    return [r1, r2].sort(BN.cmp);
  }

  _getEndoBasis(lambda) {
    // Compute endomorphic basis.
    //
    // This essentially computes Cornacchia's algorithm
    // for solving x^2 + d * y^2 = m (d = lambda, m = order).
    //
    // https://en.wikipedia.org/wiki/Cornacchia%27s_algorithm
    //
    // [GECC] Algorithm 3.74, Page 127, Section 3.5.
    // [GLV] Page 196, Section 4 (Decomposing K).
    //
    // Balanced length-two representation of a multiplier.
    //
    // 1. Run the extended euclidean algorithm with inputs n
    //    and lambda. The algorithm produces a sequence of
    //    equations si*n + ti*lam = ri where s0=1, t0=0,
    //    r0=n, s1=0, t1=1, r1=lam, and the remainders ri
    //    and are non-negative and strictly decreasing. Let
    //    l be the greatest index for which rl >= sqrt(n).
    const [rl, tl, rl1, tl1, rl2, tl2] = this._egcdSqrt(lambda);

    // 2. Set (a1, b1) <- (rl+1, -tl+1).
    const a1 = rl1;
    const b1 = tl1.neg();

    // 3. If (rl^2 + tl^2) <= (rl+2^2 + tl+2^2)
    //    then set (a2, b2) <- (rl, -tl).
    //    else set (a2, b2) <- (rl+2, -tl+2).
    const lhs = rl.sqr().iadd(tl.sqr());
    const rhs = rl2.sqr().iadd(tl2.sqr());

    let a2, b2;

    if (lhs.cmp(rhs) <= 0) {
      a2 = rl;
      b2 = tl.neg();
    } else {
      a2 = rl2;
      b2 = tl2.neg();
    }

    return [
      new Vector(a1, b1),
      new Vector(a2, b2)
    ];
  }

  _egcdSqrt(lambda) {
    // Extended Euclidean algorithm for integers.
    //
    // [GECC] Algorithm 2.19, Page 40, Section 2.2.
    // [GLV] Page 196, Section 4 (Decomposing K).
    assert(lambda instanceof BN);
    assert(!lambda.red);
    assert(lambda.sign() > 0);
    assert(this.n.sign() > 0);

    // Note that we insert the approximate square
    // root checks as described in algorithm 3.74.
    //
    // Algorithm 2.19 is defined as:
    //
    // 1. u <- a
    //    v <- b
    //
    // 2. x1 <- 1
    //    y1 <- 0
    //    x2 <- 0
    //    y2 <- 1
    //
    // 3. while u != 0 do
    //
    // 3.1. q <- floor(v / u)
    //      r <- v - q * u
    //      x <- x2 - q * x1
    //      y <- y2 - q * y1
    //
    // 3.2. v <- u
    //      u <- r
    //      x2 <- x1
    //      x1 <- x
    //      y2 <- y1
    //      y1 <- y
    //
    // 4. d <- v
    //    x <- x2
    //    y <- y2
    //
    // 5. Return (d, x, y).

    // Start with an approximate square root of n.
    const sqrtn = this.n.ushrn(this.n.bitLength() >>> 1);

    let u = lambda; // r1
    let v = this.n.clone(); // r0
    let x1 = new BN(1); // t1
    let y1 = new BN(0); // t0
    let x2 = new BN(0); // s1
    let y2 = new BN(1); // s0

    // All vectors are roots of: a + b * lambda = 0 (mod n).
    let rl, tl;

    // First vector.
    let rl1, tl1;

    // Inner.
    let i = 0;
    let j = 0;
    let p;

    // Compute EGCD.
    while (!u.isZero() && i < 2) {
      const q = v.quo(u);
      const r = v.sub(q.mul(u));
      const x = x2.sub(q.mul(x1));
      const y = y2.sub(q.mul(y1));

      // Check for r < sqrt(n).
      if (j === 0 && r.cmp(sqrtn) < 0) {
        rl = p;
        tl = x1;
        rl1 = r;
        tl1 = x;
        j = 1; // 1 more round.
      }

      p = r;
      v = u;
      u = r;
      x2 = x1;
      x1 = x;
      y2 = y1;
      y1 = y;

      i += j;
    }

    // Should never happen.
    assert(j !== 0, 'Could not find r < sqrt(n).');

    // Second vector.
    const rl2 = x2;
    const tl2 = x1;

    return [
      rl,
      tl,
      rl1,
      tl1,
      rl2,
      tl2
    ];
  }

  _getEndoPrecomp(basis) {
    // Precompute `g1` and `g2` to avoid round division.
    //
    // [JCEN12] Page 5, Section 4.3.
    //
    // Computation:
    //
    //   d = a1 * b2 - b1 * a2
    //   t = ceil(log2(d+1)) + p
    //   g1 = round((2^t * b2) / d)
    //   g2 = round((2^t * b1) / d)
    //
    // Where:
    //
    //   `p` is the number of precision bits.
    //   `d` is equal to `n` (the curve order).
    //
    // The paper above uses 2 as the value of `p`,
    // whereas libsecp256k1 uses 128 (total=384).
    //
    // We pick precision for `g1` and `g2` such that:
    //
    //   abs(g1) < n
    //   abs(g2) < n
    //
    // This ensures maximum precision for the constants
    // while also ensuring they fit into a fixed number
    // of scalar limbs in more optimized implementations.
    //
    // Furthermore, we attempt to align to a limb width
    // of 64 bits. This allows us to optimize the shift,
    // a la libsecp256k1[1].
    //
    // [1] https://github.com/bitcoin-core/secp256k1/pull/822
    assert(Array.isArray(basis));
    assert(basis.length === 2);
    assert(basis[0] instanceof Vector);
    assert(basis[1] instanceof Vector);

    const [v1, v2] = basis;
    const d = v1.a.mul(v2.b).isub(v1.b.mul(v2.a));
    const bits = d.bitLength();
    const align = bits >= 160;

    assert(d.eq(this.n));

    // Start with a rough estimate.
    let shift = bits + Math.ceil(bits / 2) + 1;
    let g1, g2;

    if (align)
      shift -= shift & 63;

    while (shift > bits) {
      g1 = v2.b.ushln(shift).divRound(d);
      g2 = v1.b.ushln(shift).divRound(d);

      if (g1.ucmp(d) < 0 && g2.ucmp(d) < 0)
        break;

      if (align)
        shift -= 64;
      else
        shift -= 1;
    }

    if (shift <= bits)
      throw new Error('Could not calculate g1 and g2.');

    return [shift, g1, g2];
  }

  _endoSplit(k) {
    // Balanced length-two representation of a multiplier.
    //
    // [GECC] Algorithm 3.74, Page 127, Section 3.5.
    //
    // Also note that it is possible to precompute[1]
    // values in order to avoid the division[2][3][4].
    //
    // This involves precomputing `g1` and `g2 (see
    // above). `c1` and `c2` can then be computed as
    // follows:
    //
    //   t = ceil(log2(n+1)) + p
    //   c1 = (k * g1) >> t
    //   c2 = -((k * g2) >> t)
    //
    // Where `>>` is an _unsigned_ right shift. Also
    // note that the last bit discarded in the shift
    // must be stored. If it is 1, then add 1 to the
    // scalar (absolute addition).
    //
    // It's worth noting that libsecp256k1 uses a
    // different calculation along the lines of:
    //
    //   t = ceil(log2(n+1)) + p
    //   c1 = ((k * g1) >> t) * -b1
    //   c2 = ((k * -g2) >> t) * -b2
    //   k2 = c1 + c2
    //   k1 = k2 * -lambda + k
    //
    // So, in the future, we can consider changing
    // step 4 to:
    //
    //   4. Compute c1 = (k * g1) >> t
    //          and c2 = -((k * g2) >> t).
    //
    //   const [shift, g1, g2] = this.endo.pre;
    //   const c1 = k.mulShift(g1, shift);
    //   const c2 = k.mulShift(g2, shift).ineg();
    //
    // Once we're brave enough, that is.
    //
    // [1] [JCEN12] Page 5, Section 4.3.
    // [2] https://github.com/bitcoin-core/secp256k1/blob/0b70241/src/scalar_impl.h#L259
    // [3] https://github.com/bitcoin-core/secp256k1/pull/21
    // [4] https://github.com/bitcoin-core/secp256k1/pull/127
    assert(k instanceof BN);
    assert(!k.red);
    assert(!this.n.isZero());

    const [v1, v2] = this.endo.basis;

    // 4. Compute c1 = round(b2 * k / n)
    //        and c2 = round(-b1 * k / n).
    const c1 = v2.b.mul(k).divRound(this.n);
    const c2 = v1.b.neg().mul(k).divRound(this.n);

    // 5. Compute k1 = k - c1 * a1 - c2 * a2
    //        and k2 = -c1 * b1 - c2 * b2.
    const p1 = c1.mul(v1.a);
    const p2 = c2.mul(v2.a);
    const q1 = c1.ineg().mul(v1.b);
    const q2 = c2.mul(v2.b);

    // Calculate answer.
    const k1 = k.sub(p1).isub(p2);
    const k2 = q1.isub(q2);

    // 6. Return (k1, k2).
    return [k1, k2];
  }

  _endoBeta(point) {
    assert(point instanceof ShortPoint);
    return [point, point._getBeta()];
  }

  _endoWnafMulAdd(points, coeffs) {
    // Point multiplication with efficiently computable endomorphisms.
    //
    // [GECC] Algorithm 3.77, Page 129, Section 3.5.
    // [GLV] Page 193, Section 3 (Using Efficient Endomorphisms).
    //
    // Note it may be possible to do this 4-dimensionally [4GLV].
    assert(Array.isArray(points));
    assert(Array.isArray(coeffs));
    assert(points.length === coeffs.length);
    assert(this.endo != null);

    const len = points.length;
    const npoints = new Array(len * 2);
    const ncoeffs = new Array(len * 2);

    for (let i = 0; i < len; i++) {
      const [p1, p2] = this._endoBeta(points[i]);
      const [k1, k2] = this._endoSplit(coeffs[i]);

      npoints[i * 2 + 0] = p1;
      ncoeffs[i * 2 + 0] = k1;
      npoints[i * 2 + 1] = p2;
      ncoeffs[i * 2 + 1] = k2;
    }

    return this._wnafMulAdd(5, npoints, ncoeffs);
  }

  _sswu(u) {
    // Simplified Shallue-Woestijne-Ulas Method.
    //
    // Distribution: 3/8.
    //
    // [SSWU1] Page 15-16, Section 7. Appendix G.
    // [SSWU2] Page 5, Theorem 2.3.
    // [H2EC] "Simplified Shallue-van de Woestijne-Ulas Method".
    //
    // Assumptions:
    //
    //   - a != 0, b != 0.
    //   - Let z be a non-square in F(p).
    //   - z != -1.
    //   - The polynomial g(x) - z is irreducible over F(p).
    //   - g(b / (z * a)) is square in F(p).
    //   - u != 0, u != +-sqrt(-1 / z).
    //
    // Map:
    //
    //   g(x) = x^3 + a * x + b
    //   t1 = 1 / (z^2 * u^4 + z * u^2)
    //   x1 = (-b / a) * (1 + t1)
    //   x1 = b / (z * a), if t1 = 0
    //   x2 = z * u^2 * x1
    //   x = x1, if g(x1) is square
    //     = x2, otherwise
    //   y = sign(u) * abs(sqrt(g(x)))
    const {b, z, ai, zi, one} = this;
    const z2 = z.redSqr();
    const ba = b.redNeg().redMul(ai);
    const bza = b.redMul(zi).redMul(ai);
    const u2 = u.redSqr();
    const u4 = u2.redSqr();
    const t0 = z2.redMul(u4).redIAdd(z.redMul(u2));
    const t1 = t0.isZero() ? t0 : t0.redInvert();
    const x1 = t1.isZero() ? bza : ba.redMul(one.redAdd(t1));
    const x2 = z.redMul(u2).redMul(x1);
    const y1 = this.solveY2(x1);
    const y2 = this.solveY2(x2);
    const alpha = y1.redIsSquare() | 0;
    const x = [x1, x2][alpha ^ 1];
    const y = [y1, y2][alpha ^ 1].redSqrt();

    if (y.redIsOdd() !== u.redIsOdd())
      y.redINeg();

    return this.point(x, y);
  }

  _sswui(p, hint) {
    // Inverting the Map (Simplified Shallue-Woestijne-Ulas).
    //
    // Assumptions:
    //
    //   - a^2 * x^2 - 2 * a * b * x - 3 * b^2 is square in F(p).
    //   - If r < 3 then x != -b / a.
    //
    // Unlike SVDW, the preimages here are evenly
    // distributed (more or less). SSWU covers ~3/8
    // of the curve points. Each preimage has a 1/2
    // chance of mapping to either x1 or x2.
    //
    // Assuming the point is within that set, each
    // point has a 1/4 chance of inverting to any
    // of the preimages. This means we can simply
    // randomly select a preimage if one exists.
    //
    // However, the [SVDW2] sampling method seems
    // slighly faster in practice for [SQUARED].
    //
    // Map:
    //
    //   c = sqrt(a^2 * x^2 - 2 * a * b * x - 3 * b^2)
    //   u1 = -(a * x + b - c) / (2 * (a * x + b) * z)
    //   u2 = -(a * x + b + c) / (2 * (a * x + b) * z)
    //   u3 = -(a * x + b - c) / (2 * b * z)
    //   u4 = -(a * x + b + c) / (2 * b * z)
    //   r = random integer in [1,4]
    //   u = sign(y) * abs(sqrt(ur))
    const {a, b, z} = this;
    const {x, y} = p;
    const r = hint & 3;
    const a2x2 = a.redSqr().redMul(x.redSqr());
    const abx2 = a.redMul(b).redMul(x).redIMuln(2);
    const b23 = b.redSqr().redMuln(3);
    const axb = a.redMul(x).redIAdd(b);
    const c = a2x2.redISub(abx2).redISub(b23).redSqrt();
    const n0 = axb.redSub(c).redINeg();
    const n1 = axb.redAdd(c).redINeg();
    const d0 = axb.redMul(z).redIMuln(2);
    const d1 = b.redMul(z).redIMuln(2);
    const n = [n0, n1][r & 1]; // r = 1 or 3
    const d = [d0, d1][r >>> 1]; // r = 2 or 3
    const u = n.redDivSqrt(d);

    if (u.redIsOdd() !== y.redIsOdd())
      u.redINeg();

    return u;
  }

  _svdwf(u) {
    // Shallue-van de Woestijne Method.
    //
    // Distribution: 9/16.
    //
    // [SVDW1] Section 5.
    // [SVDW2] Page 8, Section 3.
    //         Page 15, Section 6, Algorithm 1.
    // [H2EC] "Shallue-van de Woestijne Method".
    //
    // Assumptions:
    //
    //   - p = 1 (mod 3).
    //   - a = 0, b != 0.
    //   - Let z be a unique element in F(p).
    //   - g((sqrt(-3 * z^2) - z) / 2) is square in F(p).
    //   - u != 0, u != +-sqrt(-g(z)).
    //
    // Map:
    //
    //   g(x) = x^3 + b
    //   c = sqrt(-3 * z^2)
    //   t1 = u^2 + g(z)
    //   t2 = 1 / (u^2 * t1)
    //   t3 = u^4 * t2 * c
    //   x1 = (c - z) / 2 - t3
    //   x2 = t3 - (c + z) / 2
    //   x3 = z - t1^3 * t2 / (3 * z^2)
    //   x = x1, if g(x1) is square
    //     = x2, if g(x2) is square
    //     = x3, otherwise
    //   y = sign(u) * abs(sqrt(g(x)))
    const {c, z, zi, i2, i3} = this;
    const gz = this.solveY2(z);
    const z3 = i3.redMul(zi.redSqr());
    const u2 = u.redSqr();
    const u4 = u2.redSqr();
    const t1 = u2.redAdd(gz);
    const u2t1 = u2.redMul(t1);
    const t2 = u2t1.isZero() ? u2t1 : u2t1.redInvert();
    const t3 = u4.redMul(t2).redMul(c);
    const t4 = t1.redSqr().redMul(t1);
    const x1 = c.redSub(z).redMul(i2).redISub(t3);
    const x2 = t3.redSub(c.redAdd(z).redMul(i2));
    const x3 = z.redSub(t4.redMul(t2).redMul(z3));
    const y1 = this.solveY2(x1);
    const y2 = this.solveY2(x2);
    const y3 = this.solveY2(x3);
    const alpha = y1.redJacobi() | 1;
    const beta = y2.redJacobi() | 1;
    const i = mod((alpha - 1) * beta, 3);
    const x = [x1, x2, x3][i];
    const y = [y1, y2, y3][i];

    return [x, y];
  }

  _svdw(u) {
    const [x, yy] = this._svdwf(u);
    const y = yy.redSqrt();

    if (y.redIsOdd() !== u.redIsOdd())
      y.redINeg();

    return this.point(x, y);
  }

  _svdwi(p, hint) {
    // Inverting the Map (Shallue-van de Woestijne).
    //
    // [SQUARED] Algorithm 1, Page 8, Section 3.3.
    // [SVDW2] Page 12, Section 5.
    // [SVDW3] "Inverting the map".
    //
    // Assumptions:
    //
    //   - If r = 1 then x != -(c + z) / 2.
    //   - If r = 2 then x != (c - z) / 2.
    //   - If r > 2 then (t0 - t1 + t2) is square in F(p).
    //   - f(f^-1(x)) = x where f is the map function.
    //
    // We use the sampling method from [SVDW2],
    // _not_ [SQUARED]. This seems to have a
    // better distribution in practice.
    //
    // Note that [SVDW3] also appears to be
    // incorrect in terms of distribution.
    //
    // The distribution of f(u), assuming u is
    // random, is (1/2, 1/4, 1/4).
    //
    // To mirror this, f^-1(x) should simply
    // pick (1/2, 1/4, 1/8, 1/8).
    //
    // To anyone running the forward map, our
    // strings will appear to be random.
    //
    // Map:
    //
    //   g(x) = x^3 + b
    //   c = sqrt(-3 * z^2)
    //   t0 = 9 * (x^2 * z^2 + z^4)
    //   t1 = 18 * x * z^3
    //   t2 = 12 * g(z) * (x - z)
    //   t3 = sqrt(t0 - t1 + t2)
    //   t4 = t3 * z
    //   u1 = g(z) * (c - 2 * x - z) / (c + 2 * x + z)
    //   u2 = g(z) * (c + 2 * x + z) / (c - 2 * x - z)
    //   u3 = (3 * (z^3 - x * z^2) - 2 * g(z) + t4) / 2
    //   u4 = (3 * (z^3 - x * z^2) - 2 * g(z) - t4) / 2
    //   r = random integer in [1,4]
    //   u = sign(y) * abs(sqrt(ur))
    const {b, c, z, zero, two} = this;
    const {x, y} = p;
    const r = hint & 3;
    const z2 = z.redSqr();
    const z3 = z2.redMul(z);
    const z4 = z2.redSqr();
    const gz = z3.redAdd(b);
    const gz2 = gz.redMuln(2);
    const xx = x.redSqr();
    const x2z = x.redMuln(2).redIAdd(z);
    const xz2 = x.redMul(z2);
    const c0 = c.redSub(x2z);
    const c1 = c.redAdd(x2z);
    const t0 = xx.redMul(z2).redIAdd(z4).redIMuln(9);
    const t1 = x.redMul(z3).redIMuln(18);
    const t2 = gz.redMul(x.redSub(z)).redIMuln(12);
    const t3 = r >= 2 ? t0.redISub(t1).redIAdd(t2).redSqrt() : zero;
    const t4 = t3.redMul(z);
    const t5 = z3.redISub(xz2).redIMuln(3).redISub(gz2);
    const n0 = gz.redMul(c0);
    const n1 = gz.redMul(c1);
    const n2 = t5.redAdd(t4);
    const n3 = t5.redSub(t4);
    const d2 = two;
    const n = [n0, n1, n2, n3][r];
    const d = [c1, c0, d2, d2][r];
    const u = n.redDivSqrt(d);
    const [x0] = this._svdwf(u);

    if (!x0.eq(x))
      throw new Error('Invalid point.');

    if (u.redIsOdd() !== y.redIsOdd())
      u.redINeg();

    return u;
  }

  isElliptic() {
    const {a, b} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const b2 = b.redSqr();
    const d = b2.redMuln(27).redIAdd(a3.redMuln(4));

    // 4 * a^3 + 27 * b^2 != 0
    return !d.isZero();
  }

  jinv() {
    // [ARITH1] Page 71, Section 4.4.
    // http://mathworld.wolfram.com/j-Invariant.html
    const {a, b} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const b2 = b.redSqr();
    const t0 = a3.redMuln(4);
    const lhs = t0.redMuln(1728);
    const rhs = b2.redMuln(27).redIAdd(t0);

    if (rhs.isZero())
      throw new Error('Curve is not elliptic.');

    // (1728 * 4 * a^3) / (4 * a^3 + 27 * b^2)
    return lhs.redDiv(rhs).fromRed();
  }

  point(x, y) {
    return new ShortPoint(this, x, y);
  }

  jpoint(x, y, z) {
    return new JPoint(this, x, y, z);
  }

  solveX(y) {
    assert(y instanceof BN);

    if (!this.a.isZero())
      throw new Error('Not implemented.');

    // x^3 = y^2 - b
    const y2 = y.redSqr();
    const x3 = y2.redSub(this.b);

    return cubeRoots(x3);
  }

  solveY2(x) {
    // [GECC] Page 89, Section 3.2.2.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw.html
    assert(x instanceof BN);

    // y^2 = x^3 + a * x + b
    const x3 = x.redSqr().redMul(x);
    const y2 = x3.redIAdd(this.b);

    if (!this.zeroA) {
      // Save some cycles for a = -3.
      if (this.threeA)
        y2.redIAdd(x.redMuln(-3));
      else
        y2.redIAdd(this.a.redMul(x));
    }

    return y2;
  }

  validate(point) {
    assert(point instanceof ShortPoint);

    if (point.inf)
      return true;

    const {x, y} = point;
    const y2 = this.solveY2(x);

    return y.redSqr().eq(y2);
  }

  pointFromX(x, sign = null) {
    assert(x instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!x.red)
      x = x.toRed(this.red);

    const y = this.solveY(x);

    if (sign != null) {
      if (this.h.cmpn(1) > 0) {
        if (y.isZero() && sign)
          throw new Error('Invalid point.');
      }

      if (y.redIsOdd() !== sign)
        y.redINeg();
    }

    return this.point(x, y);
  }

  pointFromY(y, index = 0) {
    assert(y instanceof BN);
    assert((index >>> 0) === index);

    if (!y.red)
      y = y.toRed(this.red);

    const coords = this.solveX(y);

    if (index >= coords.length)
      throw new Error('Invalid X coordinate index.');

    const x = coords[index];

    return this.point(x, y);
  }

  isIsomorphic(curve) {
    // [GECC] Page 84, Section 3.1.5.
    // [ARITH1] Page 286, Section 13.2.3.c.
    assert(curve instanceof Curve);

    if (!curve.p.eq(this.p))
      return false;

    let u2, u3;
    try {
      [u2, u3] = this._scale(curve);
    } catch (e) {
      return false;
    }

    // E(a,b) <-> E(au^4,bu^6)
    if (curve.type === 'short') {
      // a' = a * u^4, b' = b * u^6
      const a = this.field(curve.a).redMul(u2.redSqr());
      const b = this.field(curve.b).redMul(u3.redSqr());

      return this.a.eq(a) && this.b.eq(b);
    }

    // E(a,b) <-> M(A,B)
    if (curve.type === 'mont') {
      // (A / (3 * B))^3 + a * (A / (3 * B)) + b = 0
      const {a3, bi} = curve;
      const x = this.field(a3.redMul(bi)).redMul(u2);
      const y2 = this.solveY2(x);

      return y2.isZero();
    }

    // E(a,b) <-> E(a,d)
    if (curve.type === 'edwards') {
      // ((a' + d') / 6)^3 + a * ((a' + d') / 6) + b = 0
      const x = this.field(curve.ad6).redMul(u2);
      const y2 = this.solveY2(x);

      return y2.isZero();
    }

    return false;
  }

  isIsogenous(curve) {
    assert(curve instanceof Curve);
    return false;
  }

  pointFromShort(point) {
    // [GECC] Page 84, Section 3.1.5.
    // [ALT] Appendix F.3 (Isomorphic Mapping between Weierstrass Curves).
    assert(point instanceof ShortPoint);

    if (this.isIsomorphic(point.curve)) {
      // Isomorphic maps for E(a,b)<->E(au^4,bu^6):
      //
      //   x' = x * u^2
      //   y' = y * u^3
      //
      // Where a * u^4 = a' and b * u^6 = b'.
      if (point.isInfinity())
        return this.point();

      const [u2, u3] = this._scale(point.curve);
      const x = this.field(point.x);
      const y = this.field(point.y);
      const nx = x.redMul(u2);
      const ny = y.redMul(u3);

      return this.point(nx, ny);
    }

    throw new Error('Not implemented.');
  }

  pointFromMont(point) {
    // [ALT] Appendix E.2 (Switching between Alternative Representations).
    // [MONT2] "Equivalence with Weierstrass curves"
    assert(point instanceof MontPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for M(A,B)->E(a,b):
      //
      //   x = (u + A / 3) / B
      //   y = v / B
      //
      // Undefined if ((u^3 + A * u^2 + u) / B) is not square.
      if (point.isInfinity())
        return this.point();

      const {a3, bi} = point.curve;
      const [u2, u3] = this._scale(point.curve);
      const nx = point.x.redAdd(a3).redMul(bi);
      const ny = point.y.redMul(bi);

      return this.point(this.field(nx).redMul(u2),
                        this.field(ny).redMul(u3));
    }

    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    // [TWISTEQ] Section 2.
    assert(point instanceof EdwardsPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for E(a,d)->E(a',b'):
      //
      //   x' = ((5 * d - a) * y + d - 5 * a) / (12 * (y - 1))
      //   y' = (d - a) * (y + 1) / (4 * x * (y - 1))
      //
      // Undefined for x = 0 or y = 1.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> ((a + d) / 6, 0)
      //
      // Unexceptional Cases:
      //   - (sqrt(1 / a), 0) -> ((5 * a - d) / 12, (a - d) / 4 * sqrt(a))
      const {a, d, ad6} = point.curve;
      const [u2, u3] = this._scale(point.curve);

      if (point.isInfinity())
        return this.point();

      if (point.x.isZero()) {
        const x = this.field(ad6).redMul(u2);
        return this.point(x, this.zero);
      }

      const {x, y, z} = point;
      const a5 = a.redMuln(5);
      const d5 = d.redMuln(5);
      const dma = d.redSub(a);
      const d5a = d5.redSub(a);
      const da5 = d.redSub(a5);
      const ypz = y.redAdd(z);
      const ymz = y.redSub(z);
      const xx = d5a.redMul(y).redIAdd(da5.redMul(z));
      const xz = ymz.redMuln(12);
      const yy = dma.redMul(ypz).redMul(z);
      const yz = ymz.redMul(x).redIMuln(4);

      return this.cpoint(this.field(xx).redMul(u2),
                         this.field(xz),
                         this.field(yy).redMul(u3),
                         this.field(yz));
    }

    throw new Error('Not implemented.');
  }

  pointFromUniform(u) {
    assert(u instanceof BN);

    // z = 0 or b = 0
    if (this.z.isZero() || this.b.isZero())
      throw new Error('Not implemented.');

    // a != 0, b != 0
    if (!this.a.isZero())
      return this._sswu(u);

    // p = 1 mod 3, a = 0, b != 0
    if (!this.c.isZero())
      return this._svdw(u);

    throw new Error('Not implemented.');
  }

  pointToUniform(p, hint) {
    // Convert a short weierstrass point to a field
    // element by inverting either the SSWU or SVDW
    // map.
    //
    // Hint Layout:
    //
    //   [00000000] [0000] [0000]
    //        |        |      |
    //        |        |      +-- preimage index
    //        |        +--- subgroup
    //        +-- bits to OR with uniform bytes
    assert(p instanceof ShortPoint);
    assert((hint >>> 0) === hint);

    // z = 0 or b = 0
    if (this.z.isZero() || this.b.isZero())
      throw new Error('Not implemented.');

    // P = O
    if (p.isInfinity())
      throw new Error('Invalid point.');

    // Add a random torsion component.
    const i = ((hint >>> 4) & 15) % this.torsion.length;
    const q = p.add(this.torsion[i]);

    return wrapErrors(() => {
      // a != 0, b != 0
      if (!this.a.isZero())
        return this._sswui(q, hint);

      // p = 1 mod 3, a = 0, b != 0
      if (!this.c.isZero())
        return this._svdwi(q, hint);

      throw new Error('Not implemented.');
    });
  }

  mulAll(points, coeffs) {
    return super.mulAll(points, coeffs).toP();
  }

  affinizeAll(points) {
    const out = this.normalizeAll(points);

    for (let i = 0; i < out.length; i++)
      out[i] = out[i].toP();

    return out;
  }

  decodePoint(bytes) {
    return ShortPoint.decode(this, bytes);
  }

  encodeX(point) {
    assert(point instanceof Point);
    return point.encodeX();
  }

  decodeEven(bytes) {
    return ShortPoint.decodeEven(this, bytes);
  }

  decodeSquare(bytes) {
    return ShortPoint.decodeSquare(this, bytes);
  }

  toShort(a0, odd, sign = null) {
    const [a, b] = this._short(a0, odd);

    const curve = new ShortCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = curve._scale(this);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromShort(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromShort(this.torsion[i]);

    return curve;
  }

  toMont(b0, odd, sign = null) {
    const [a, b] = this._mont(b0, odd);

    const curve = new MontCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = this._scale(curve);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromShort(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromShort(this.torsion[i]);

    return curve;
  }

  toEdwards(a0, odd, sign = null) {
    const [a, d] = this._edwards(a0, odd);

    const curve = new EdwardsCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      d: d,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = this._scale(curve);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity()) {
      curve.g = curve.pointFromShort(this.g);
      curve.g.normalize();
    }

    if (curve.isComplete()) {
      for (let i = 0; i < this.h.word(0); i++) {
        curve.torsion[i] = curve.pointFromShort(this.torsion[i]);
        curve.torsion[i].normalize();
      }
    }

    return curve;
  }

  pointFromJSON(json) {
    return ShortPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);

    json.a = this.a.fromRed().toJSON();
    json.b = this.b.fromRed().toJSON();

    if (!this.c.isZero())
      json.c = this.c.fromRed().toJSON();

    return json;
  }
}

/**
 * ShortPoint
 */

class ShortPoint extends Point {
  constructor(curve, x, y) {
    assert(curve instanceof ShortCurve);

    super(curve, types.AFFINE);

    this.x = this.curve.zero;
    this.y = this.curve.zero;
    this.inf = true;

    if (x != null)
      this._init(x, y);
  }

  _init(x, y) {
    assert(x instanceof BN);
    assert(y instanceof BN);

    this.x = x;
    this.y = y;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    this.inf = false;
  }

  _getBeta() {
    if (!this.curve.endo)
      return null;

    if (this.pre && this.pre.beta)
      return this.pre.beta;

    // Augment the point with our beta value.
    // This is the counterpart to `k2` after
    // the endomorphism split of `k`.
    //
    // Note that if we have precomputation,
    // we have to clone and update all of the
    // precomputed points below.
    const xb = this.x.redMul(this.curve.endo.beta);
    const beta = this.curve.point(xb, this.y);

    if (this.pre) {
      beta.pre = this.pre.map((point) => {
        const xb = point.x.redMul(this.curve.endo.beta);
        return this.curve.point(xb, point.y);
      });

      this.pre.beta = beta;
    }

    return beta;
  }

  _getJNAF(point) {
    assert(point instanceof ShortPoint);

    if (this.inf || point.inf)
      return super._getJNAF(point);

    // Create comb for JSF.
    const comb = [
      this, // 1
      null, // 3
      null, // 5
      point // 7
    ];

    // Try to avoid Jacobian points, if possible.
    if (this.y.eq(point.y)) {
      comb[1] = this.add(point);
      comb[2] = this.toJ().sub(point);
    } else if (this.y.eq(point.y.redNeg())) {
      comb[1] = this.toJ().add(point);
      comb[2] = this.sub(point);
    } else {
      comb[1] = this.toJ().add(point);
      comb[2] = this.toJ().sub(point);
    }

    return comb;
  }

  clone() {
    if (this.inf)
      return this.curve.point();

    return this.curve.point(this.x, this.y);
  }

  scale(a) {
    return this.toJ().scale(a);
  }

  neg() {
    // P = O
    if (this.inf)
      return this;

    // -(X1, Y1) = (X1, -Y1)
    return this.curve.point(this.x, this.y.redNeg());
  }

  add(p) {
    // [GECC] Page 80, Section 3.1.2.
    //
    // Addition Law:
    //
    //   l = (y1 - y2) / (x1 - x2)
    //   x3 = l^2 - x1 - x2
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 2M + 1S + 6A
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P, P + -P
    if (this.x.eq(p.x)) {
      // P + -P = O
      if (!this.y.eq(p.y))
        return this.curve.point();

      // P + P = 2P
      return this.dbl();
    }

    // X1 != X2, Y1 = Y2
    if (this.y.eq(p.y)) {
      // X3 = -X1 - X2
      const nx = this.x.redNeg().redISub(p.x);

      // Y3 = -Y1
      const ny = this.y.redNeg();

      // Skip the inverse.
      return this.curve.point(nx, ny);
    }

    // H = X1 - X2
    const h = this.x.redSub(p.x);

    // R = Y1 - Y2
    const r = this.y.redSub(p.y);

    // L = R / H
    const l = r.redDiv(h);

    // X3 = L^2 - X1 - X2
    const nx = l.redSqr().redISub(this.x).redISub(p.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dbl() {
    // [GECC] Page 80, Section 3.1.2.
    //
    // Addition Law (doubling):
    //
    //   l = (3 * x1^2 + a) / (2 * y1)
    //   x3 = l^2 - 2 * x1
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 2M + 2S + 3A + 2*2 + 1*3

    // P = O
    if (this.inf)
      return this;

    // Y1 = 0
    if (this.y.isZero())
      return this.curve.point();

    // XX = X1^2
    const xx = this.x.redSqr();

    // M = 3 * XX + a
    const m = xx.redIMuln(3).redIAdd(this.curve.a);

    // Z = 2 * Y1
    const z = this.y.redMuln(2);

    // L = M / Z
    const l = m.redDiv(z);

    // X3 = L^2 - 2 * X1
    const nx = l.redSqr().redISub(this.x).redISub(this.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dblp(pow) {
    return this.toJ().dblp(pow).toP();
  }

  getX() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.x.fromRed();
  }

  getY() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof ShortPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.inf)
      return p.inf;

    // Q = O
    if (p.inf)
      return false;

    // X1 = X2, Y1 = Y2
    return this.x.eq(p.x)
        && this.y.eq(p.y);
  }

  cmp(point) {
    assert(point instanceof ShortPoint);

    if (this.inf && !point.inf)
      return -1;

    if (!this.inf && point.inf)
      return 1;

    if (this.inf && point.inf)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX())
        || this.getY().cmp(point.getY());
  }

  isInfinity() {
    // Infinity cannot be represented in
    // the affine space, except by a flag.
    return this.inf;
  }

  isOrder2() {
    if (this.inf)
      return false;

    return this.y.isZero();
  }

  isOdd() {
    if (this.inf)
      return false;

    return this.y.redIsOdd();
  }

  isEven() {
    if (this.inf)
      return false;

    return this.y.redIsEven();
  }

  isSquare() {
    if (this.inf)
      return false;

    return this.y.redJacobi() !== -1;
  }

  eqX(x) {
    assert(x instanceof BN);
    assert(!x.red);

    if (this.inf)
      return false;

    return this.getX().eq(x);
  }

  eqR(x) {
    assert(x instanceof BN);
    assert(!x.red);
    assert(!this.curve.n.isZero());

    if (this.inf)
      return false;

    return this.getX().imod(this.curve.n).eq(x);
  }

  mul(k) {
    return super.mul(k).toP();
  }

  muln(k) {
    return super.muln(k).toP();
  }

  mulBlind(k, rng) {
    return super.mulBlind(k, rng).toP();
  }

  mulAdd(k1, p2, k2) {
    return super.mulAdd(k1, p2, k2).toP();
  }

  mulH() {
    return super.mulH().toP();
  }

  div(k) {
    return super.div(k).toP();
  }

  divn(k) {
    return super.divn(k).toP();
  }

  divH() {
    return super.divH().toP();
  }

  toP() {
    return this;
  }

  toJ() {
    // (X3, Y3, Z3) = (1, 1, 0)
    if (this.inf)
      return this.curve.jpoint();

    // (X3, Y3, Z3) = (X1, Y1, 1)
    return this.curve.jpoint(this.x, this.y, this.curve.one);
  }

  encode(compact) {
    // [SEC1] Page 10, Section 2.3.3.
    if (compact == null)
      compact = true;

    assert(typeof compact === 'boolean');

    const {fieldSize} = this.curve;

    // We do not serialize points at infinity.
    if (this.inf)
      throw new Error('Invalid point.');

    // Compressed form (0x02 = even, 0x03 = odd).
    if (compact) {
      const p = Buffer.alloc(1 + fieldSize);
      const x = this.curve.encodeField(this.getX());

      p[0] = 0x02 | this.y.redIsOdd();
      x.copy(p, 1);

      return p;
    }

    // Uncompressed form (0x04).
    const p = Buffer.alloc(1 + fieldSize * 2);
    const x = this.curve.encodeField(this.getX());
    const y = this.curve.encodeField(this.getY());

    p[0] = 0x04;
    x.copy(p, 1);
    y.copy(p, 1 + fieldSize);

    return p;
  }

  static decode(curve, bytes) {
    // [SEC1] Page 11, Section 2.3.4.
    assert(curve instanceof ShortCurve);
    assert(Buffer.isBuffer(bytes));

    const len = curve.fieldSize;

    if (bytes.length < 1 + len)
      throw new Error('Not a point.');

    // Point forms:
    //
    //   0x00 -> Infinity (openssl, unsupported)
    //   0x02 -> Compressed Even
    //   0x03 -> Compressed Odd
    //   0x04 -> Uncompressed
    //   0x06 -> Hybrid Even (openssl)
    //   0x07 -> Hybrid Odd (openssl)
    //
    // Note that openssl supports serializing points
    // at infinity as {0}. We choose not to support it
    // because it's strange and not terribly useful.
    const form = bytes[0];

    switch (form) {
      case 0x02:
      case 0x03: {
        if (bytes.length !== 1 + len)
          throw new Error('Invalid point size for compressed.');

        const x = curve.decodeField(bytes.slice(1, 1 + len));

        if (x.cmp(curve.p) >= 0)
          throw new Error('Invalid point.');

        const p = curve.pointFromX(x, form === 0x03);

        assert(!p.isInfinity());

        return p;
      }

      case 0x04:
      case 0x06:
      case 0x07: {
        if (bytes.length !== 1 + len * 2)
          throw new Error('Invalid point size for uncompressed.');

        const x = curve.decodeField(bytes.slice(1, 1 + len));
        const y = curve.decodeField(bytes.slice(1 + len, 1 + 2 * len));

        // [GECC] Algorithm 4.3, Page 180, Section 4.
        if (x.cmp(curve.p) >= 0 || y.cmp(curve.p) >= 0)
          throw new Error('Invalid point.');

        // OpenSSL hybrid encoding.
        if (form !== 0x04 && form !== (0x06 | y.isOdd()))
          throw new Error('Invalid hybrid encoding.');

        const p = curve.point(x, y);

        if (!p.validate())
          throw new Error('Invalid point.');

        assert(!p.isInfinity());

        return p;
      }

      default: {
        throw new Error('Unknown point format.');
      }
    }
  }

  encodeX() {
    // [SCHNORR] "Specification".
    // [BIP340] "Specification".
    return this.curve.encodeField(this.getX());
  }

  static decodeEven(curve, bytes) {
    // [BIP340] "Specification".
    assert(curve instanceof ShortCurve);

    const x = curve.decodeField(bytes);

    if (x.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    return curve.pointFromX(x, false);
  }

  static decodeSquare(curve, bytes) {
    // [SCHNORR] "Specification".
    assert(curve instanceof ShortCurve);

    const x = curve.decodeField(bytes);

    if (x.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    return curve.pointFromX(x);
  }

  toJSON(pre) {
    if (this.inf)
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    if (pre === true && this.pre)
      return [x, y, this.pre.toJSON()];

    return [x, y];
  }

  toPretty() {
    if (this.inf)
      return [];

    const size = this.curve.fieldSize * 2;
    const x = toPretty(this.getX(), size);
    const y = toPretty(this.getY(), size);

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof ShortCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);
    const point = curve.point(x, y);

    if (json.length > 2 && json[2] != null)
      point.pre = Precomp.fromJSON(point, json[2]);

    return point;
  }

  [custom]() {
    if (this.inf)
      return '<ShortPoint: Infinity>';

    return '<ShortPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
  }
}

/**
 * JPoint
 */

class JPoint extends Point {
  constructor(curve, x, y, z) {
    assert(curve instanceof ShortCurve);

    super(curve, types.JACOBIAN);

    this.x = this.curve.one;
    this.y = this.curve.one;
    this.z = this.curve.zero;
    this.zOne = false;

    if (x != null)
      this._init(x, y, z);
  }

  _init(x, y, z) {
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(z == null || (z instanceof BN));

    this.x = x;
    this.y = y;
    this.z = z || this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);
  }

  clone() {
    return this.curve.jpoint(this.x, this.y, this.z);
  }

  validate() {
    // [GECC] Example 3.20, Page 88, Section 3.
    const {a, b} = this.curve;

    // P = O
    if (this.isInfinity())
      return true;

    // Z1 = 1
    if (this.zOne)
      return this.curve.validate(this.toP());

    // y^2 = x^3 + a * x * z^4 + b * z^6
    const lhs = this.y.redSqr();
    const x3 = this.x.redSqr().redMul(this.x);
    const z2 = this.z.redSqr();
    const z4 = z2.redSqr();
    const z6 = z4.redMul(z2);
    const rhs = x3.redIAdd(b.redMul(z6));

    if (!this.curve.zeroA) {
      // Save some cycles for a = -3.
      if (this.curve.threeA)
        rhs.redIAdd(z4.redIMuln(-3).redMul(this.x));
      else
        rhs.redIAdd(a.redMul(z4).redMul(this.x));
    }

    return lhs.eq(rhs);
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#scaling-z
    // 1I + 3M + 1S

    // Z = 1
    if (this.zOne)
      return this;

    // P = O
    if (this.isInfinity())
      return this;

    // A = 1 / Z1
    const a = this.z.redInvert();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1 * AA
    this.x = this.x.redMul(aa);

    // Y3 = Y1 * AA * A
    this.y = this.y.redMul(aa).redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // P = O
    if (this.isInfinity())
      return this.curve.jpoint();

    // AA = A^2
    const aa = a.redSqr();

    // X3 = X1 * AA
    const nx = this.x.redMul(aa);

    // Y3 = Y1 * AA * A
    const ny = this.y.redMul(aa).redMul(a);

    // Z3 = Z1 * A
    const nz = this.z.redMul(a);

    return this.curve.jpoint(nx, ny, nz);
  }

  neg() {
    // -(X1, Y1, Z1) = (X1, -Y1, Z1)
    return this.curve.jpoint(this.x, this.y.redNeg(), this.z);
  }

  add(p) {
    assert(p instanceof Point);

    if (p.type === types.AFFINE)
      return this._mixedAdd(p);

    return this._add(p);
  }

  _add(p) {
    assert(p instanceof JPoint);

    // O + P = P
    if (this.isInfinity())
      return p;

    // P + O = P
    if (p.isInfinity())
      return this;

    // Z1 = 1
    if (this.zOne)
      return p._addJA(this);

    // Z2 = 1
    if (p.zOne)
      return this._addJA(p);

    return this._addJJ(p);
  }

  _mixedAdd(p) {
    assert(p instanceof ShortPoint);

    // O + P = P
    if (this.isInfinity())
      return p.toJ();

    // P + O = P
    if (p.isInfinity())
      return this;

    return this._addJA(p);
  }

  _addJJ(p) {
    // No assumptions.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
    // 12M + 4S + 6A + 1*2 (implemented as: 12M + 4S + 7A)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // Z2Z2 = Z2^2
    const z2z2 = p.z.redSqr();

    // U1 = X1 * Z2Z2
    const u1 = this.x.redMul(z2z2);

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S1 = Y1 * Z2 * Z2Z2
    const s1 = this.y.redMul(p.z).redMul(z2z2);

    // S2 = Y2 * Z1 * Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2 - U1
    const h = u2.redISub(u1);

    // r = S2 - S1
    const r = s2.redISub(s1);

    // H = 0
    if (h.isZero()) {
      if (!r.isZero())
        return this.curve.jpoint();

      return this.dbl();
    }

    // HH = H^2
    const hh = h.redSqr();

    // HHH = H * HH
    const hhh = h.redMul(hh);

    // V = U1 * HH
    const v = u1.redMul(hh);

    // X3 = r^2 - HHH - 2 * V
    const nx = r.redSqr().redISub(hhh).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - S1 * HHH
    const ny = r.redMul(v.redISub(nx)).redISub(s1.redMul(hhh));

    // Z3 = Z1 * Z2 * H
    const nz = this.z.redMul(p.z).redMul(h);

    return this.curve.jpoint(nx, ny, nz);
  }

  _addJA(p) {
    // Assumes Z2 = 1.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd
    // 8M + 3S + 6A + 5*2 (implemented as: 8M + 3S + 7A + 4*2)

    // Z1Z1 = Z1^2
    const z1z1 = this.z.redSqr();

    // U2 = X2 * Z1Z1
    const u2 = p.x.redMul(z1z1);

    // S2 = Y2 * Z1 * Z1Z1
    const s2 = p.y.redMul(this.z).redMul(z1z1);

    // H = U2 - X1
    const h = u2.redISub(this.x);

    // r = 2 * (S2 - Y1)
    const r = s2.redISub(this.y).redIMuln(2);

    // H = 0
    if (h.isZero()) {
      if (!r.isZero())
        return this.curve.jpoint();

      return this.dbl();
    }

    // I = (2 * H)^2
    const i = h.redMuln(2).redSqr();

    // J = H * I
    const j = h.redMul(i);

    // V = X1 * I
    const v = this.x.redMul(i);

    // X3 = r^2 - J - 2 * V
    const nx = r.redSqr().redISub(j).redISub(v).redISub(v);

    // Y3 = r * (V - X3) - 2 * Y1 * J
    const ny = r.redMul(v.redISub(nx)).redISub(this.y.redMul(j).redIMuln(2));

    // Z3 = 2 * Z1 * H
    const nz = this.z.redMul(h).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  dbl() {
    // P = O
    if (this.isInfinity())
      return this;

    // Y1 = 0
    if (this.y.isZero())
      return this.curve.jpoint();

    // a = 0
    if (this.curve.zeroA)
      return this._dbl0();

    // a = -3
    if (this.curve.threeA)
      return this._dbl3();

    return this._dblJ();
  }

  _dblJ() {
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2
    // 3M + 6S + 4A + 1*a + 2*2 + 1*3 + 1*4 + 1*8
    // (implemented as: 3M + 6S + 5A + 1*a + 1*2 + 1*3 + 1*4 + 1*8)

    // XX = X1^2
    const xx = this.x.redSqr();

    // YY = Y1^2
    const yy = this.y.redSqr();

    // ZZ = Z1^2
    const zz = this.z.redSqr();

    // S = 4 * X1 * YY
    const s = this.x.redMul(yy).redIMuln(4);

    // M = 3 * XX + a * ZZ^2
    const m = xx.redIMuln(3).redIAdd(this.curve.a.redMul(zz.redSqr()));

    // T = M^2 - 2 * S
    const t = m.redSqr().redISub(s).redISub(s);

    // X3 = T
    const nx = t;

    // Y3 = M * (S - T) - 8 * YY^2
    const ny = m.redMul(s.redISub(t)).redISub(yy.redSqr().redIMuln(8));

    // Z3 = 2 * Y1 * Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl0() {
    // Assumes a = 0.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    // 2M + 5S + 6A + 3*2 + 1*3 + 1*8
    // (implemented as: 2M + 5S + 7A + 2*2 + 1*3 + 1*8)

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = B^2
    const c = b.redSqr();

    // + XB2 = (X1 + B)^2
    const xb2 = b.redIAdd(this.x).redSqr();

    // D = 2 * ((X1 + B)^2 - A - C)
    const d = xb2.redISub(a).redISub(c).redIMuln(2);

    // E = 3 * A
    const e = a.redIMuln(3);

    // F = E^2
    const f = e.redSqr();

    // X3 = F - 2 * D
    const nx = f.redISub(d).redISub(d);

    // Y3 = E * (D - X3) - 8 * C
    const ny = e.redMul(d.redISub(nx)).redISub(c.redIMuln(8));

    // Z3 = 2 * Y1 * Z1
    const nz = this.y.redMul(this.z).redIMuln(2);

    return this.curve.jpoint(nx, ny, nz);
  }

  _dbl3() {
    // Assumes a = -3.
    // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    // 3M + 5S + 8A + 1*3 + 1*4 + 2*8
    // (implemented as: 3M + 5S + 8A + 1*2 + 1*3 + 1*4 + 1*8)

    // delta = Z1^2
    const delta = this.z.redSqr();

    // gamma = Y1^2
    const gamma = this.y.redSqr();

    // beta = X1 * gamma
    const beta = this.x.redMul(gamma);

    // + xmdelta = X1 - delta
    const xmdelta = this.x.redSub(delta);

    // + xpdelta = X1 + delta
    const xpdelta = this.x.redAdd(delta);

    // alpha = 3 * (X1 - delta) * (X1 + delta)
    const alpha = xmdelta.redMul(xpdelta).redIMuln(3);

    // + beta4 = 4 * beta
    const beta4 = beta.redIMuln(4);

    // + beta8 = 2 * beta4
    const beta8 = beta4.redMuln(2);

    // + gamma28 = 8 * gamma^2
    const gamma28 = gamma.redSqr().redIMuln(8);

    // X3 = alpha^2 - 8 * beta
    const nx = alpha.redSqr().redISub(beta8);

    // Z3 = (Y1 + Z1)^2 - gamma - delta
    const nz = this.y.redAdd(this.z).redSqr().redISub(gamma).redISub(delta);

    // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
    const ny = alpha.redMul(beta4.redISub(nx)).redISub(gamma28);

    return this.curve.jpoint(nx, ny, nz);
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof JPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.isInfinity())
      return p.isInfinity();

    // Q = O
    if (p.isInfinity())
      return false;

    // Z1 = Z2
    if (this.z.eq(p.z)) {
      return this.x.eq(p.x)
          && this.y.eq(p.y);
    }

    // X1 * Z2^2 = X2 * Z1^2
    const zz1 = this.z.redSqr();
    const zz2 = p.z.redSqr();
    const x1 = this.x.redMul(zz2);
    const x2 = p.x.redMul(zz1);

    if (!x1.eq(x2))
      return false;

    // Y1 * Z2^3 = Y2 * Z1^3
    const zzz1 = zz1.redMul(this.z);
    const zzz2 = zz2.redMul(p.z);
    const y1 = this.y.redMul(zzz2);
    const y2 = p.y.redMul(zzz1);

    return y1.eq(y2);
  }

  cmp(point) {
    assert(point instanceof JPoint);

    const inf1 = this.isInfinity();
    const inf2 = point.isInfinity();

    if (inf1 && !inf2)
      return -1;

    if (!inf1 && inf2)
      return 1;

    if (inf1 && inf2)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX())
        || this.getY().cmp(point.getY());
  }

  isInfinity() {
    // Z1 = 0
    return this.z.isZero();
  }

  isOrder2() {
    if (this.isInfinity())
      return false;

    return this.y.isZero();
  }

  isOdd() {
    if (this.isInfinity())
      return false;

    this.normalize();

    return this.y.redIsOdd();
  }

  isEven() {
    if (this.isInfinity())
      return false;

    this.normalize();

    return this.y.redIsEven();
  }

  isSquare() {
    if (this.isInfinity())
      return false;

    return this.y.redMul(this.z).redJacobi() !== -1;
  }

  eqX(x) {
    // Verify that integer `x` is equal to field
    // element `x` by scaling it by our z coordinate.
    // This optimization is mentioned in and used for
    // bip-schnorr[1]. This avoids having to affinize
    // the resulting point during verification.
    //
    // [1] [SCHNORR] "Optimizations".
    assert(x instanceof BN);
    assert(!x.red);

    if (this.isInfinity())
      return false;

    const zz = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zz);

    return this.x.eq(rx);
  }

  eqR(x) {
    // Similar to the optimization above, this
    // optimization, suggested by Maxwell[1],
    // compares an integer to an X coordinate
    // by scaling it.
    //
    // Since a signature's R value is modulo N
    // in ECDSA, we may be dealing with an R
    // value greater than N in actuality.
    //
    // If the equality check fails, we can
    // scale N itself by Z and add it to the
    // X field element.
    //
    // [1] https://github.com/bitcoin-core/secp256k1/commit/ce7eb6f
    assert(x instanceof BN);
    assert(!x.red);

    if (!this.curve.smallGap)
      return this.toP().eqR(x);

    if (this.isInfinity())
      return false;

    if (x.cmp(this.curve.p) >= 0)
      return false;

    const zz = this.z.redSqr();
    const rx = x.toRed(this.curve.red).redMul(zz);

    if (this.x.eq(rx))
      return true;

    if (this.curve.highOrder)
      return false;

    if (x.cmp(this.curve.pmodn) >= 0)
      return false;

    const rn = this.curve.redN.redMul(zz);

    rx.redIAdd(rn);

    return this.x.eq(rx);
  }

  toP() {
    // P = O
    if (this.isInfinity())
      return this.curve.point();

    this.normalize();

    // (X3, Y3) = (X1 / Z1^2, Y1 / Z1^3)
    return this.curve.point(this.x, this.y);
  }

  toJ() {
    return this;
  }

  encode(compact) {
    return this.toP().encode(compact);
  }

  static decode(curve, bytes) {
    return ShortPoint.decode(curve, bytes).toJ();
  }

  encodeX() {
    return this.toP().encodeX();
  }

  static decodeEven(curve, bytes) {
    return ShortPoint.decodeEven(curve, bytes).toJ();
  }

  static decodeSquare(curve, bytes) {
    return ShortPoint.decodeSquare(curve, bytes).toJ();
  }

  toJSON(pre) {
    return this.toP().toJSON(pre);
  }

  toPretty() {
    return this.toP().toPretty();
  }

  static fromJSON(curve, json) {
    return ShortPoint.fromJSON(curve, json).toJ();
  }

  [custom]() {
    if (this.isInfinity())
      return '<JPoint: Infinity>';

    return '<JPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + ' z=' + this.z.fromRed().toString(16, 2)
         + '>';
  }
}

/**
 * MontCurve
 */

class MontCurve extends Curve {
  constructor(conf) {
    super(MontPoint, 'mont', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.b = BN.fromJSON(conf.b).toRed(this.red);

    this.bi = this.b.redInvert();
    this.a2 = this.a.redAdd(this.two);
    this.a24 = this.a2.redMul(this.i4);
    this.a3 = this.a.redMul(this.i3);
    this.a0 = this.a.redMul(this.bi);
    this.b0 = this.bi.redSqr();

    this._finalize(conf);
  }

  static _isomorphism(curveA, curveB, customB) {
    // Montgomery Isomorphism.
    //
    // [MONT3] Page 3, Section 2.1.
    //
    // Transformation:
    //
    //   A' = A
    //   B' = B'
    //
    // Where (B / B') is square.
    assert(curveA instanceof BN);
    assert(curveB instanceof BN);
    assert(customB instanceof BN);

    const a = curveA.clone();
    const b = customB.clone();
    const c = curveB.redDiv(customB);

    if (c.redJacobi() !== 1)
      throw new Error('Invalid `b` coefficient.');

    return [a, b];
  }

  _short(a0, odd) {
    // Montgomery->Short Weierstrass Equivalence.
    //
    // [MONT2] "Equivalence with Weierstrass curves".
    //
    // Transformation:
    //
    //   a = (3 - A^2) / (3 * B^2)
    //   b = (2 * A^3 - 9 * A) / (27 * B^3)
    const {a, b, three} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const b2 = b.redSqr();
    const b3 = b2.redMul(b);
    const n0 = three.redSub(a2);
    const d0 = b2.redMuln(3);
    const n1 = a3.redMuln(2).redISub(a.redMuln(9));
    const d1 = b3.redMuln(27);
    const wa = n0.redDiv(d0);
    const wb = n1.redDiv(d1);

    if (a0 != null)
      return ShortCurve._isomorphism(wa, wb, a0, odd);

    return [wa, wb];
  }

  _mont(b0) {
    return MontCurve._isomorphism(this.a, this.b, b0);
  }

  _edwards(a0, invert = false) {
    // Montgomery->Twisted Edwards Transformation.
    //
    // [MONT1] Page 11, Section 4.3.5.
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    //
    // Equivalence:
    //
    //   a = (A + 2) / B
    //   d = (A - 2) / B
    //
    // Isomorphism:
    //
    //   a = a'
    //   d = a' * (A - 2) / (A + 2)
    //
    // Where ((A + 2) / (B * a')) is square.
    //
    // If `d` is square, we can usually find
    // a complete curve by using the `invert`
    // option. This will create an isomorphism
    // chain of: M(A,B)->E(a,d)->E(d,a).
    //
    // The equivalence between E(a,d) and
    // E(d,a) is:
    //
    //   (x, y) = (x, 1 / y)
    //
    // Meaning our map to E(d,a) is:
    //
    //   x = u / v
    //   y = 1 / ((u - 1) / (u + 1))
    //     = (u + 1) / (u - 1)
    assert(typeof invert === 'boolean');

    const {two, bi} = this;
    const a = this.a.redAdd(two).redMul(bi);
    const d = this.a.redSub(two).redMul(bi);

    if (invert)
      a.swap(d);

    if (a0 != null)
      return EdwardsCurve._isomorphism(a, d, a0);

    return [a, d];
  }

  _scaleShort(curve) {
    assert(curve instanceof ShortCurve);

    const [u2, u3] = curve._scale(this);

    return [this.field(u2.redInvert()),
            this.field(u3.redInvert())];
  }

  _scaleMont(curve) {
    // We can extract the isomorphism factor with:
    //
    //   c = +-sqrt(B / B')
    //
    // If base points are available, we can do:
    //
    //   c = v' / v
    assert(curve instanceof MontCurve);

    if (this.g.isInfinity() || curve.g.isInfinity())
      return this.field(curve.b).redDivSqrt(this.b);

    return this.g.y.redDiv(this.field(curve.g.y));
  }

  _scaleEdwards(curve, invert) {
    // We _could_ do something like:
    //
    //   B = 4 / (a - d)
    //   c = +-sqrt(B / B')
    //
    // Which can be reduced to:
    //
    //   c = +-sqrt(4 / ((a - d) * B'))
    //
    // If base points are available:
    //
    //   v = u' / x
    //   c = v' / v
    //
    // Which can be reduced to:
    //
    //   c = v' * x / u'
    //
    // However, the way our maps are
    // written, we can re-use the Edwards
    // isomorphism factor when going the
    // other direction.
    assert(curve instanceof EdwardsCurve);

    const c = curve._scale(this, invert);

    return this.field(c);
  }

  _solveY0(x) {
    assert(x instanceof BN);

    // y^2 = x^3 + A * x^2 + B * x
    const a = this.a0;
    const b = this.b0;
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const y2 = x3.redIAdd(a.redMul(x2)).redIAdd(b.redMul(x));

    return y2;
  }

  _elligator2(u) {
    // Elligator 2.
    //
    // Distribution: 1/2.
    //
    // [ELL2] Page 11, Section 5.2.
    // [H2EC] "Elligator 2 Method".
    //        "Mappings for Montgomery curves".
    // [SAFE] "Indistinguishability from uniform random strings".
    //
    // Assumptions:
    //
    //   - y^2 = x^3 + A * x^2 + B * x.
    //   - A != 0, B != 0.
    //   - A^2 - 4 * B is non-zero and non-square in F(p).
    //   - Let z be a non-square in F(p).
    //   - u != +-sqrt(-1 / z).
    //
    // Note that Elligator 2 is defined over the form:
    //
    //   y'^2 = x'^3 + A' * x'^2 + B' * x'
    //
    // Instead of:
    //
    //   B * y^2 = x^3 + A * x^2 + x
    //
    // Where:
    //
    //   A' = A / B
    //   B' = 1 / B^2
    //   x' = x / B
    //   y' = y / B
    //
    // And:
    //
    //   x = B * x'
    //   y = B * y'
    //
    // This is presumably the result of Elligator 2
    // being designed in long Weierstrass form. If
    // we want to support B != 1, we need to do the
    // conversion.
    //
    // Map:
    //
    //   g(x) = x^3 + A * x^2 + B * x
    //   x1 = -A / (1 + z * u^2)
    //   x1 = -A, if x1 = 0
    //   x2 = -x1 - A
    //   x = x1, if g(x1) is square
    //     = x2, otherwise
    //   y = sign(u) * abs(sqrt(g(x)))
    const lhs = this.a0.redNeg();
    const rhs = this.one.redAdd(this.z.redMul(u.redSqr()));

    if (rhs.isZero())
      rhs.inject(this.one);

    const x1 = lhs.redMul(rhs.redInvert());
    const x2 = x1.redNeg().redISub(this.a0);
    const y1 = this._solveY0(x1);
    const y2 = this._solveY0(x2);
    const alpha = y1.redIsSquare() | 0;
    const x0 = [x1, x2][alpha ^ 1];
    const y0 = [y1, y2][alpha ^ 1].redSqrt();

    if (y0.redIsOdd() !== u.redIsOdd())
      y0.redINeg();

    const x = this.b.redMul(x0);
    const y = this.b.redMul(y0);

    return this.point(x, y);
  }

  _invert2(p, hint) {
    // Inverting the Map (Elligator 2).
    //
    // [ELL2] Page 12, Section 5.3.
    //
    // Assumptions:
    //
    //   - -z * x * (x + A) is square in F(p).
    //   - If r = 1 then x != 0.
    //   - If r = 2 then x != -A.
    //
    // Map:
    //
    //   u1 = -(x + A) / (x * z)
    //   u2 = -x / ((x + A) * z)
    //   r = random integer in [1,2]
    //   u = sign(y) * abs(sqrt(ur))
    //
    // Note that `0 / 0` can only occur if A = 0
    // (this violates the assumptions of Elligator 2).
    const {x, y} = p;
    const r = hint & 1;
    const x0 = x.redMul(this.bi);
    const y0 = y.redMul(this.bi);
    const n = x0.redAdd(this.a0);
    const d = x0;
    const lhs = [n, d][r].redINeg();
    const rhs = [d, n][r].redMul(this.z);
    const u = lhs.redDivSqrt(rhs);

    if (u.redIsOdd() !== y0.redIsOdd())
      u.redINeg();

    return u;
  }

  isElliptic() {
    const a2 = this.a.redSqr();
    const d = this.b.redMul(a2.redSub(this.four));

    // B * (A^2 - 4) != 0
    return !d.isZero();
  }

  jinv() {
    // [MONT3] Page 3, Section 2.
    const {a, three, four} = this;
    const a2 = a.redSqr();
    const t0 = a2.redSub(three);
    const lhs = t0.redPown(3).redIMuln(256);
    const rhs = a2.redSub(four);

    if (rhs.isZero())
      throw new Error('Curve is not elliptic.');

    // (256 * (A^2 - 3)^3) / (A^2 - 4)
    return lhs.redDiv(rhs).fromRed();
  }

  point(x, y) {
    return new MontPoint(this, x, y);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  xpoint(x, z) {
    return new XPoint(this, x, z);
  }

  solveY2(x) {
    // [MONT3] Page 3, Section 2.
    // https://hyperelliptic.org/EFD/g1p/auto-montgom.html
    assert(x instanceof BN);

    // B * y^2 = x^3 + A * x^2 + x
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const by2 = x3.redIAdd(this.a.redMul(x2)).redIAdd(x);
    const y2 = by2.redMul(this.bi);

    return y2;
  }

  validate(point) {
    assert(point instanceof MontPoint);

    if (point.isInfinity())
      return true;

    const {x, y} = point;
    const y2 = this.solveY2(x);

    return y.redSqr().eq(y2);
  }

  pointFromX(x, sign = null) {
    assert(x instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!x.red)
      x = x.toRed(this.red);

    const y = this.solveY(x);

    if (sign != null) {
      if (y.isZero() && sign)
        throw new Error('Invalid point.');

      if (y.redIsOdd() !== sign)
        y.redINeg();
    }

    return this.point(x, y);
  }

  isIsomorphic(curve, invert) {
    // [MONT3] Page 3, Section 2.1.
    assert(curve instanceof Curve);

    if (!curve.p.eq(this.p))
      return false;

    // M(A,B) <-> M(A,B')
    if (curve.type === 'mont') {
      const a = this.field(curve.a);
      const b = this.field(curve.b);

      // A' = A
      if (!this.a.eq(a))
        return false;

      // B' != 0
      if (this.b.isZero())
        return false;

      // jacobi(B / B') = 1
      const c = b.redDiv(this.b);

      return c.redJacobi() === 1;
    }

    return curve.isIsomorphic(this, invert);
  }

  isIsogenous(curve) {
    assert(curve instanceof Curve);

    if (curve.type === 'mont')
      return false;

    return curve.isIsogenous(this);
  }

  pointFromShort(point) {
    // [ALT] Appendix E.2 (Switching between Alternative Representations).
    // [MONT2] "Equivalence with Weierstrass curves"
    assert(point instanceof ShortPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for E(a,b)->M(A,B):
      //
      //   u = B * x - A / 3
      //   v = B * y
      //
      // Undefined if ((u^3 + A * u^2 + u) / B) is not square.
      if (point.isInfinity())
        return this.point();

      const {a3, b} = this;
      const [u2, u3] = this._scale(point.curve);
      const x = this.field(point.x).redMul(u2);
      const y = this.field(point.y).redMul(u3);
      const u = b.redMul(x).redISub(a3);
      const v = b.redMul(y);

      return this.point(u, v);
    }

    throw new Error('Not implemented.');
  }

  pointFromMont(point) {
    // [MONT3] Page 3, Section 2.1.
    assert(point instanceof MontPoint);

    if (this.isIsomorphic(point.curve)) {
      // Isomorphic maps for M(A,B)<->M(A,B'):
      //
      //   u' = u
      //   v' = +-sqrt(B / B') * v
      //
      // Undefined if (B / B') is not square.
      if (point.isInfinity())
        return this.point();

      const c = this._scale(point.curve);
      const u = this.field(point.x);
      const v = this.field(point.y);
      const nu = u;
      const nv = c.redMul(v);

      return this.point(nu, nv);
    }

    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    // [RFC7748] Section 4.1 & 4.2.
    // [MONT3] Page 6, Section 2.5.
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    assert(point instanceof EdwardsPoint);
    assert(point.curve.p.eq(this.p));

    // Edwards `x`, `y`, `z`.
    const x = this.field(point.x);
    const y = this.field(point.y);
    const z = this.field(point.z);

    if (this.isIsogenous(point.curve)) {
      // 4-isogeny maps for E(1,d)->M(2-4d,1):
      //
      //   u = y^2 / x^2
      //   v = (2 - x^2 - y^2) * y / x^3
      //
      // Undefined for x = 0.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> (0, 0)
      //
      // Unexceptional Cases:
      //   - (+-1, 0) -> (0, 0)
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.zero);

      const c = z.redSqr().redIMuln(2);
      const uu = y.redSqr();
      const uz = x.redSqr();
      const vv = c.redISub(uz).redISub(uu).redMul(y);
      const vz = uz.redMul(x);

      return this.cpoint(uu, uz, vv, vz);
    }

    if (this.isIsomorphic(point.curve, true)) {
      // Isomorphic maps for E(d,a)->M(A,B):
      //
      //   u = (y + 1) / (y - 1)
      //   v = +-sqrt((A - 2) / (B * a)) * u / x
      //
      // Undefined for x = 0 or y = 1.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> (0, 0)
      //
      // Unexceptional Cases:
      //   - (+-sqrt(1 / a), 0) -> (-1, +-sqrt((A - 2) / B))
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.zero);

      const c = this._scale(point.curve, true);
      const uu = y.redAdd(z);
      const uz = y.redSub(z);
      const vv = c.redMul(z).redMul(uu);
      const vz = x.redMul(uz);

      return this.cpoint(uu, uz, vv, vz);
    }

    if (this.isIsomorphic(point.curve, false)) {
      // Isomorphic maps for E(a,d)->M(A,B):
      //
      //   u = (1 + y) / (1 - y)
      //   v = +-sqrt((A + 2) / (B * a)) * u / x
      //
      // Undefined for x = 0 or y = 1.
      //
      // Exceptional Cases:
      //   - (0, 1) -> O
      //   - (0, -1) -> (0, 0)
      //
      // Unexceptional Cases:
      //   - (+-sqrt(1 / a), 0) -> (1, +-sqrt((A + 2) / B))
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.zero);

      const c = this._scale(point.curve, false);
      const uu = z.redAdd(y);
      const uz = z.redSub(y);
      const vv = c.redMul(z).redMul(uu);
      const vz = x.redMul(uz);

      return this.cpoint(uu, uz, vv, vz);
    }

    throw new Error('Not implemented.');
  }

  pointFromUniform(u) {
    assert(u instanceof BN);

    // z = 0 or A = 0
    if (this.z.isZero() || this.a.isZero())
      throw new Error('Not implemented.');

    return this._elligator2(u);
  }

  pointToUniform(p, hint) {
    // Convert a montgomery point to a field
    // element by inverting the elligator2 map.
    //
    // Hint Layout:
    //
    //   [00000000] [0000] [0000]
    //        |        |      |
    //        |        |      +-- preimage index
    //        |        +--- subgroup
    //        +-- bits to OR with uniform bytes
    assert(p instanceof MontPoint);
    assert((hint >>> 0) === hint);

    // z = 0 or A = 0
    if (this.z.isZero() || this.a.isZero())
      throw new Error('Not implemented.');

    // P = O
    if (p.isInfinity())
      throw new Error('Invalid point.');

    // Add a random torsion component.
    const i = ((hint >>> 4) & 15) % this.torsion.length;
    const q = p.add(this.torsion[i]);

    return wrapErrors(() => {
      return this._invert2(q, hint);
    });
  }

  decodePoint(bytes, sign) {
    return MontPoint.decode(this, bytes, sign);
  }

  encodeX(point) {
    assert(point instanceof XPoint);
    return point.encode();
  }

  decodeX(bytes) {
    return XPoint.decode(this, bytes);
  }

  toShort(a0, odd, sign = null) {
    const [a, b] = this._short(a0, odd);

    const curve = new ShortCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = curve._scale(this);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromMont(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromMont(this.torsion[i]);

    return curve;
  }

  toMont(b0, sign = null) {
    const [a, b] = this._mont(b0);

    const curve = new MontCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = curve._scale(this);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromMont(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromMont(this.torsion[i]);

    return curve;
  }

  toEdwards(a0, invert, sign = null) {
    const [a, d] = this._edwards(a0, invert);

    const curve = new EdwardsCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      d: d,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = curve._scale(this, invert);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity()) {
      curve.g = curve.pointFromMont(this.g);
      curve.g.normalize();
    }

    if (curve.isComplete()) {
      for (let i = 0; i < this.h.word(0); i++) {
        curve.torsion[i] = curve.pointFromMont(this.torsion[i]);
        curve.torsion[i].normalize();
      }
    }

    return curve;
  }

  pointFromJSON(json) {
    return MontPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);
    json.a = this.a.fromRed().toJSON();
    json.b = this.b.fromRed().toJSON();
    return json;
  }
}

/**
 * MontPoint
 */

class MontPoint extends Point {
  constructor(curve, x, y) {
    assert(curve instanceof MontCurve);

    super(curve, types.AFFINE);

    this.x = this.curve.zero;
    this.y = this.curve.zero;
    this.inf = true;

    if (x != null)
      this._init(x, y);
  }

  _init(x, y) {
    assert(x instanceof BN);
    assert(y instanceof BN);

    this.x = x;
    this.y = y;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    this.inf = false;
  }

  clone() {
    if (this.inf)
      return this.curve.point();

    return this.curve.point(this.x, this.y);
  }

  scale(a) {
    return this.clone();
  }

  randomize(rng) {
    return this.clone();
  }

  neg() {
    // P = O
    if (this.inf)
      return this;

    // -(X1, Y1) = (X1, -Y1)
    return this.curve.point(this.x, this.y.redNeg());
  }

  add(p) {
    // [MONT1] Page 8, Section 4.3.2.
    //
    // Addition Law:
    //
    //   l = (y2 - y1) / (x2 - x1)
    //   x3 = b * l^2 - a - x1 - x2
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 2M + 1S + 7A + 1*b
    assert(p instanceof MontPoint);

    // O + P = P
    if (this.inf)
      return p;

    // P + O = P
    if (p.inf)
      return this;

    // P + P, P + -P
    if (this.x.eq(p.x)) {
      // P + -P = O
      if (!this.y.eq(p.y))
        return this.curve.point();

      // P + P = 2P
      return this.dbl();
    }

    // H = X2 - X1
    const h = p.x.redSub(this.x);

    // R = Y2 - Y1
    const r = p.y.redSub(this.y);

    // L = R / H
    const l = r.redDiv(h);

    // K = b * L^2
    const k = this.curve.b.redMul(l.redSqr());

    // X3 = K - a - X1 - X2
    const nx = k.redISub(this.curve.a).redISub(this.x).redISub(p.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  dbl() {
    // [MONT1] Page 8, Section 4.3.2.
    //
    // Addition Law (doubling):
    //
    //   l = (3 * x1^2 + 2 * a * x1 + 1) / (2 * b * y1)
    //   x3 = b * l^2 - a - 2 * x1
    //   y3 = l * (x1 - x3) - y1
    //
    // 1I + 3M + 2S + 7A + 1*a + 1*b + 1*b + 2*2 + 1*3

    // P = O
    if (this.inf)
      return this;

    // Y1 = 0
    if (this.y.isZero())
      return this.curve.point();

    // M1 = 3 * X1^2
    const m1 = this.x.redSqr().redIMuln(3);

    // M2 = 2 * a * X1
    const m2 = this.curve.a.redMul(this.x).redIMuln(2);

    // M = M1 + M2 + 1
    const m = m1.redIAdd(m2).redIAdd(this.curve.one);

    // Z = 2 * b * Y1
    const z = this.curve.b.redMul(this.y).redIMuln(2);

    // L = M / Z
    const l = m.redDiv(z);

    // K = b * L^2
    const k = this.curve.b.redMul(l.redSqr());

    // X3 = K - a - 2 * X1
    const nx = k.redISub(this.curve.a).redISub(this.x).redISub(this.x);

    // Y3 = L * (X1 - X3) - Y1
    const ny = l.redMul(this.x.redSub(nx)).redISub(this.y);

    return this.curve.point(nx, ny);
  }

  getX() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.x.fromRed();
  }

  getY() {
    if (this.inf)
      throw new Error('Invalid point.');

    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof MontPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.inf)
      return p.inf;

    // Q = O
    if (p.inf)
      return false;

    // X1 = X2, Y1 = Y2
    return this.x.eq(p.x)
        && this.y.eq(p.y);
  }

  cmp(point) {
    assert(point instanceof MontPoint);

    if (this.inf && !point.inf)
      return -1;

    if (!this.inf && point.inf)
      return 1;

    if (this.inf && point.inf)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX())
        || this.getY().cmp(point.getY());
  }

  isInfinity() {
    // Infinity cannot be represented in
    // the affine space, except by a flag.
    return this.inf;
  }

  isOrder2() {
    if (this.inf)
      return false;

    return this.y.isZero();
  }

  isOdd() {
    if (this.inf)
      return false;

    return this.y.redIsOdd();
  }

  isEven() {
    if (this.inf)
      return false;

    return this.y.redIsEven();
  }

  toP() {
    return this;
  }

  toJ() {
    return this;
  }

  toX() {
    // (X3, Z3) = (1, 0)
    if (this.inf)
      return this.curve.xpoint();

    // (X3, Z3) = (X1, 1)
    return this.curve.xpoint(this.x, this.curve.one);
  }

  encode() {
    return this.toX().encode();
  }

  static decode(curve, bytes, sign) {
    assert(curve instanceof MontCurve);
    return curve.decodeX(bytes).toP(sign);
  }

  toJSON(pre) {
    if (this.inf)
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    return [x, y];
  }

  toPretty() {
    if (this.inf)
      return [];

    const size = this.curve.fieldSize * 2;
    const x = toPretty(this.getX(), size);
    const y = toPretty(this.getY(), size);

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof MontCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);

    return curve.point(x, y);
  }

  [custom]() {
    if (this.inf)
      return '<MontPoint: Infinity>';

    return '<MontPoint:'
         + ' x=' + this.x.fromRed().toString(16, 2)
         + ' y=' + this.y.fromRed().toString(16, 2)
         + '>';
  }
}

/**
 * XPoint
 */

class XPoint extends Point {
  constructor(curve, x, z) {
    assert(curve instanceof MontCurve);

    super(curve, types.PROJECTIVE);

    this.x = this.curve.one;
    this.z = this.curve.zero;

    if (x != null)
      this._init(x, z);
  }

  _init(x, z) {
    assert(x instanceof BN);
    assert(z == null || (z instanceof BN));

    this.x = x;
    this.z = z || this.curve.one;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);
  }

  clone() {
    return this.curve.xpoint(this.x, this.z);
  }

  precompute(power, rng) {
    // No-op.
    return this;
  }

  validate() {
    if (this.isInfinity())
      return true;

    // B * y^2 * z = x^3 + A * x^2 * z + x * z^2
    const {x, z} = this;
    const x2 = x.redSqr();
    const x3 = x2.redMul(x);
    const z2 = z.redSqr();
    const ax2 = this.curve.a.redMul(x2).redMul(z);
    const by2 = x3.redIAdd(ax2).redIAdd(x.redMul(z2));
    const y2 = by2.redMul(this.curve.bi);

    // sqrt(y^2 * z^4) = y * z^2
    return y2.redMul(z).redJacobi() !== -1;
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#scaling-scale
    // 1I + 1M

    // P = O
    if (this.isInfinity())
      return this;

    // Z1 = 1
    if (this.z.eq(this.curve.one))
      return this;

    // X3 = X1 / Z1
    this.x = this.x.redDiv(this.z);

    // Z3 = 1
    this.z = this.curve.one;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // P = O
    if (this.isInfinity())
      return this.curve.xpoint();

    // X3 = X1 * A
    const nx = this.x.redMul(a);

    // Y3 = Y1 * A
    const nz = this.z.redMul(a);

    return this.curve.xpoint(nx, nz);
  }

  neg() {
    // -(X1, Z1) = (X1, Z1)
    return this;
  }

  dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
    // 2M + 2S + 4A + 1*a24

    // A = X1 + Z1
    const a = this.x.redAdd(this.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X1 - Z1
    const b = this.x.redSub(this.z);

    // BB = B^2
    const bb = b.redSqr();

    // C = AA - BB
    const c = aa.redSub(bb);

    // X3 = AA * BB
    const nx = aa.redMul(bb);

    // Z3 = C * (BB + a24 * C)
    const nz = c.redMul(bb.redIAdd(this.curve.a24.redMul(c)));

    return this.curve.xpoint(nx, nz);
  }

  diffAddDbl(p2, p3) {
    // https://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#ladder-ladd-1987-m-3
    // 6M + 4S + 8A + 1*a24
    assert(p2 instanceof XPoint);
    assert(p3 instanceof XPoint);

    // A = X2 + Z2
    const a = p2.x.redAdd(p2.z);

    // AA = A^2
    const aa = a.redSqr();

    // B = X2 - Z2
    const b = p2.x.redSub(p2.z);

    // BB = B^2
    const bb = b.redSqr();

    // E = AA - BB
    const e = aa.redSub(bb);

    // C = X3 + Z3
    const c = p3.x.redAdd(p3.z);

    // D = X3 - Z3
    const d = p3.x.redSub(p3.z);

    // DA = D * A
    const da = d.redMul(a);

    // CB = C * B
    const cb = c.redMul(b);

    // X5 = Z1 * (DA + CB)^2
    const x5 = this.z.redMul(da.redAdd(cb).redSqr());

    // Z5 = X1 * (DA - CB)^2
    const z5 = this.x.redMul(da.redISub(cb).redSqr());

    // X4 = AA * BB
    const x4 = aa.redMul(bb);

    // Z4 = E * (BB + a24 * E)
    const z4 = e.redMul(bb.redIAdd(this.curve.a24.redMul(e)));

    return [
      this.curve.xpoint(x4, z4),
      this.curve.xpoint(x5, z5)
    ];
  }

  getX() {
    if (this.isInfinity())
      throw new Error('Invalid point.');

    this.normalize();

    return this.x.fromRed();
  }

  getY(sign) {
    return this.toP(sign).getY();
  }

  eq(p) {
    assert(p instanceof XPoint);

    // P = Q
    if (this === p)
      return true;

    // P = O
    if (this.isInfinity())
      return p.isInfinity();

    // Q = O
    if (p.isInfinity())
      return false;

    // Z1 = Z2
    if (this.z.eq(p.z))
      return this.x.eq(p.x);

    // X1 * Z2 = X2 * Z1
    const x1 = this.x.redMul(p.z);
    const x2 = p.x.redMul(this.z);

    return x1.eq(x2);
  }

  cmp(point) {
    assert(point instanceof XPoint);

    const inf1 = this.isInfinity();
    const inf2 = point.isInfinity();

    if (inf1 && !inf2)
      return -1;

    if (!inf1 && inf2)
      return 1;

    if (inf1 && inf2)
      return 0;

    return this.order().cmp(point.order())
        || this.getX().cmp(point.getX());
  }

  isInfinity() {
    // Z1 = 0
    return this.z.isZero();
  }

  isOrder2() {
    if (this.isInfinity())
      return false;

    return this.x.isZero();
  }

  isOdd() {
    return false;
  }

  isEven() {
    return false;
  }

  hasTorsion() {
    if (this.isInfinity())
      return false;

    // X1 = 0, Z1 != 0 (edge case)
    if (this.x.isZero())
      return true;

    return super.hasTorsion();
  }

  order() {
    try {
      return this.toP().order();
    } catch (e) {
      return new BN(1);
    }
  }

  jmul(k) {
    // Multiply with the Montgomery Ladder.
    //
    // [MONT3] Algorithm 4, Page 12, Section 4.2.
    //
    // Note that any clamping is meant to
    // be done _outside_ of this function.
    assert(k instanceof BN);
    assert(!k.red);

    const bits = k.bitLength();

    let a = this.curve.xpoint();
    let b = this;

    for (let i = bits - 1; i >= 0; i--) {
      const bit = k.bit(i);

      if (bit === 0)
        [a, b] = this.diffAddDbl(a, b);
      else
        [b, a] = this.diffAddDbl(b, a);
    }

    return a;
  }

  jmulBlind(k, rng) {
    if (!rng)
      return this.jmul(k);

    // Randomize if available.
    return this.randomize(rng).jmul(k);
  }

  jmulAdd(k1, p2, k2) {
    throw new Error('Not implemented.');
  }

  toP(sign = null) {
    assert(sign == null || typeof sign === 'boolean');

    if (this.isInfinity())
      return this.curve.point();

    this.normalize();

    return this.curve.pointFromX(this.x, sign);
  }

  toJ() {
    return this;
  }

  toX() {
    return this;
  }

  key() {
    if (this.isInfinity())
      return `${this.curve.uid}:oo`;

    this.normalize();

    const x = this.getX().toString(16);

    return `${this.curve.uid}:${x}`;
  }

  encode() {
    // [RFC7748] Section 5.
    return this.curve.encodeField(this.getX());
  }

  static decode(curve, bytes) {
    assert(curve instanceof MontCurve);

    // [RFC7748] Section 5.
    const x = curve.decodeField(bytes);

    // We're supposed to ignore the hi bit
    // on montgomery points... I think. If
    // we don't, the X25519 test vectors
    // break, which is pretty convincing
    // evidence. This is a no-op for X448.
    x.iumaskn(curve.fieldBits);

    // Note: montgomery points are meant to be
    // reduced by the prime and do not have to
    // be explicitly validated in order to do
    // the montgomery ladder.
    const p = curve.xpoint(x, curve.one);

    assert(!p.isInfinity());

    return p;
  }

  toJSON(pre) {
    return this.toP().toJSON(pre);
  }

  toPretty() {
    return this.toP().toPretty();
  }

  static fromJSON(curve, json) {
    return MontPoint.fromJSON(curve, json).toX();
  }

  [custom]() {
    if (this.isInfinity())
      return '<XPoint: Infinity>';

    return '<XPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }
}

/**
 * EdwardsCurve
 */

class EdwardsCurve extends Curve {
  constructor(conf) {
    super(EdwardsPoint, 'edwards', conf);

    this.a = BN.fromJSON(conf.a).toRed(this.red);
    this.d = BN.fromJSON(conf.d).toRed(this.red);
    this.s = BN.fromJSON(conf.s || '0').toRed(this.red);
    this.si = this.s.isZero() ? this.zero : this.s.redInvert();

    this.k = this.d.redMuln(2);
    this.smi = -this.d.redNeg().word(0);
    this.ad6 = this.a.redAdd(this.d).redMul(this.i6);

    this.twisted = !this.a.eq(this.one);
    this.oneA = this.a.eq(this.one);
    this.mOneA = this.a.eq(this.one.redNeg());
    this.smallD = this.prime != null && this.d.redNeg().length === 1;
    this.alt = null;

    this._finalize(conf);
  }

  static _isomorphism(curveA, curveD, customA) {
    // Twisted Edwards Isomorphism.
    //
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    //
    // Transformation:
    //
    //   a' = a'
    //   d' = a' * d / a
    //
    // Where (a / a') is square.
    assert(curveA instanceof BN);
    assert(curveD instanceof BN);
    assert(customA instanceof BN);

    const a = customA.clone();
    const d = customA.redMul(curveD).redDiv(curveA);
    const c = curveA.redDiv(customA);

    if (c.redJacobi() !== 1)
      throw new Error('Invalid `a` coefficient.');

    return [a, d];
  }

  _short(a0, odd) {
    // Twisted Edwards->Short Weierstrass Equivalence.
    //
    // [TWISTEQ] Section 2.
    //
    // Transformation:
    //
    //   a' = -(a^2 + 14 * a * d + d^2) / 48
    //   b' = (33 * (a^2 * d + a * d^2) - a^3 - d^3) / 864
    const {a, d} = this;
    const a2 = a.redSqr();
    const a3 = a2.redMul(a);
    const d2 = d.redSqr();
    const d3 = d2.redMul(d);
    const ad14 = a.redMul(d).redIMuln(14);
    const a2d = a2.redMul(d);
    const ad2 = a.redMul(d2);
    const t0 = a2d.redIAdd(ad2).redIMuln(33);
    const wa = a2.redAdd(ad14).redIAdd(d2).redDivn(-48);
    const wb = t0.redISub(a3).redISub(d3).redDivn(864);

    if (a0 != null)
      return ShortCurve._isomorphism(wa, wb, a0, odd);

    return [wa, wb];
  }

  _mont(b0, invert = false) {
    // Twisted Edwards->Montgomery Transformation.
    //
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    //
    // Equivalence:
    //
    //   A = 2 * (a + d) / (a - d)
    //   B = 4 / (a - d)
    //
    // Isomorphism:
    //
    //   A = 2 * (a + d) / (a - d)
    //   B = B'
    //
    // Where ((4 / (a - d)) / B') is square.
    //
    // If `4 / (a - d)` is non-square, we can
    // usually force B=1 by using the `invert`
    // option. This will create an isomorphism
    // chain of: E(a,d)->E(d,a)->M(-A,-B).
    //
    // The equivalence between E(a,d) and E(d,a)
    // is:
    //
    //   (x, y) = (x, 1 / y)
    //
    // Meaning our map to M(-A,-B) is:
    //
    //   u = (1 + 1 / y) / (1 - 1 / y)
    //     = (y + 1) / (y - 1)
    //   v = u / x
    assert(typeof invert === 'boolean');

    let apd, amd;

    if (invert) {
      apd = this.d.redAdd(this.a);
      amd = this.d.redSub(this.a);
    } else {
      apd = this.a.redAdd(this.d);
      amd = this.a.redSub(this.d);
    }

    const z = amd.redInvert();
    const a = apd.redMuln(2).redMul(z);
    const b = z.redMuln(4);

    if (b0 != null)
      return MontCurve._isomorphism(a, b, b0);

    return [a, b];
  }

  _edwards(a0) {
    return EdwardsCurve._isomorphism(this.a, this.d, a0);
  }

  _scaleShort(curve) {
    assert(curve instanceof ShortCurve);

    const [u2, u3] = curve._scale(this);

    return [this.field(u2.redInvert()),
            this.field(u3.redInvert())];
  }

  _scaleMont(curve, invert = false) {
    // Calculate isomorphism factor between
    // Twisted Edwards and Montgomery with:
    //
    //   a = (A + 2) / B
    //   c = +-sqrt(a / a')
    //
    // Which can be reduced to:
    //
    //   c = +-sqrt((A + 2) / (B * a'))
    //
    // If base points are available, we can do:
    //
    //   x = u / v
    //   c = x' / x
    //
    // Which can be reduced to:
    //
    //   c = v * x' / u
    //
    // We can now calculate the Edwards `x` with:
    //
    //   x' = c * u / v
    //
    // And likewise, the Montgomery `v`:
    //
    //   v = c * u / x'
    assert(curve instanceof MontCurve);
    assert(typeof invert === 'boolean');

    if (this.g.isInfinity() || curve.g.isInfinity()) {
      const [a] = curve._edwards(null, invert);

      return this.field(a).redDivSqrt(this.a);
    }

    const x = curve.g.x.redDiv(curve.g.y);

    return this.g.x.redDiv(this.field(x));
  }

  _scaleEdwards(curve) {
    // We can extract the isomorphism factor with:
    //
    //   c = +-sqrt(a / a')
    //
    // If base points are available, we can do:
    //
    //   c = x' / x
    assert(curve instanceof EdwardsCurve);

    if (this.g.isInfinity() || curve.g.isInfinity())
      return this.field(curve.a).redDivSqrt(this.a);

    return this.g.x.redDiv(this.field(curve.g.x));
  }

  _mulA(num) {
    assert(num instanceof BN);

    // n * a = n
    if (this.oneA)
      return num.clone();

    // n * a = -n
    if (this.mOneA)
      return num.redNeg();

    return this.a.redMul(num);
  }

  _mulD(num) {
    assert(num instanceof BN);

    // -d < 0x4000000
    if (this.smallD)
      return num.redMuln(this.smi);

    return this.d.redMul(num);
  }

  _elligator1(t) {
    // Elligator 1.
    //
    // Distribution: 1/2.
    //
    // [ELL1] Page 6, Section 3.
    //        Page 15, Appendix A.
    // [ELL2] Page 7, Section 3.2.
    //
    // Assumptions:
    //
    //   - Let p be a prime power congruent to 3 mod 4.
    //   - Let s be a nonzero element of F(p).
    //   - Let c = 2 / s^2.
    //   - Let r = c + 1 / c.
    //   - Let d = -(c + 1)^2 / (c - 1)^2.
    //   - (s^2 - 2) * (s^2 + 2) != 0.
    //   - c * (c - 1) * (c + 1) != 0.
    //   - r != 0.
    //   - d is not square.
    //   - x^2 + y^2 = 1 + d * x^2 * y^2.
    //   - u * v * X * Y * x * (Y + 1) != 0.
    //   - Y^2 = X^5 + (r^2 - 2) * X^3 + X.
    //
    // Elligator 1, as devised by Fouque et al,
    // takes place on the hyperelliptic curve of:
    //
    //   y^2 = x^5 + (r^2 - 2) * x^3 + x
    //
    // Not only must our Edwards curve be complete,
    // with a prime congruent to 3 mod 4, and a = 1,
    // our curve must be isomorphic to a hyperelliptic
    // curve of the above form. Roughly one half of
    // all Edwards curves are isomorphic to a curve
    // of said form.
    //
    // We can derive the isomorphism with:
    //
    //   c = (d +- 2 * sqrt(-d) - 1) / (d + 1)
    //   s = +-sqrt(2 / c)
    //   r = c + 1 / c
    //
    // Note that even if your curve is an Elligator 1
    // curve, Elligator 2 is probably still preferable,
    // as it has nearly the same properties (i.e. the
    // same distribution), and is much less complex.
    //
    // Map:
    //
    //   f(a) = a^((p - 1) / 2)
    //   u = (1 - t) / (1 + t)
    //   v = u^5 + (r^2 - 2) * u^3 + u
    //   X = f(v) * u
    //   Y = (f(v) * v)^((p + 1) / 4) * f(v) * f(u^2 + 1 / c^2)
    //   Y = 1, if u = 0
    //   x = (c - 1) * s * X * (1 + X) / Y
    //   y = (r * X - (1 + X)^2) / (r * X + (1 + X)^2)
    //
    // When t = +-1, we create the hyperelliptic
    // 2-torsion point of (0, 0). This needs to be
    // mapped to (0, -1) in Edwards form, but the x
    // denominator becomes zero. As far as I can
    // tell, this is the only exceptional case.
    //
    // The only other exceptional case initially
    // appears to be when the y denominator sums to
    // zero (when t = sqrt(4 / r + 1)), however, the
    // hyperelliptic `X` is negated by the sign of
    // `v`, making this impossible.
    const {s, si, i2, one, two} = this;
    const c = si.redSqr().redIMuln(2);
    const ci = s.redSqr().redMul(i2);
    const ci2 = ci.redSqr();
    const r = c.redAdd(ci);
    const r2 = r.redSqr().redISub(two);
    const cm1 = c.redSub(one);
    const uu = one.redSub(t);
    const uz = one.redAdd(t);
    const u = uz.isZero() ? uz : uu.redDiv(uz);
    const u2 = u.redSqr();
    const u3 = u2.redMul(u);
    const u5 = u3.redMul(u2);
    const v = u5.redAdd(r2.redMul(u3)).redIAdd(u);
    const f0 = this.field(v.redJacobi());
    const f1 = this.field(u2.redAdd(ci2).redJacobi());
    const f2 = f0.redMul(f1);
    const X = f0.redMul(u);
    const Y = f0.redMul(v).redSqrt().redMul(f2);
    const X1 = one.redAdd(X);
    const rX = r.redMul(X);
    const X12 = X1.redSqr();
    const xx = cm1.redMul(s).redMul(X).redMul(X1);
    const xz = u.isZero() ? this.one : Y;
    const yy = rX.redSub(X12);
    const yz = rX.redAdd(X12);

    return this.cpoint(xx, xz, yy, yz);
  }

  _invert1(p, hint) {
    // Inverting the Map (Elligator 1).
    //
    // [ELL1] Page 6, Section 3.
    //        Page 15, Appendix A.
    // [ELL2] Page 7, Section 3.3.
    //
    // Assumptions:
    //
    //   - y + 1 != 0.
    //   - (1 + n * r)^2 - 1 is square in F(p).
    //   - If n * r = -2 then x = 2 * s * (c - 1) * f(c) / r.
    //   - Y = (c - 1) * s * X * (1 + X) / x.
    //
    // Map:
    //
    //   f(a) = a^((p - 1) / 2)
    //   n = (y - 1) / (2 * (y + 1))
    //   X = -(1 + n * r) + ((1 + n * r)^2 - 1)^((p + 1) / 4)
    //   z = f((c - 1) * s * X * (1 + X) * x * (X^2 + 1 / c^2))
    //   u = z * X
    //   t = (1 - u) / (1 + u)
    const {s, si, i2, one} = this;
    const {x, y, z} = p;
    const sign = hint & 1;
    const c = si.redSqr().redIMuln(2);
    const ci = s.redSqr().redMul(i2);
    const ci2 = ci.redSqr();
    const r = c.redAdd(ci);
    const cm1 = c.redSub(one);
    const nn = y.redSub(z);
    const nz = y.redAdd(z).redIMuln(2);
    const n = nz.isZero() ? nz : nn.redDiv(nz);
    const nr1 = one.redAdd(n.redMul(r));
    const w2 = nr1.redSqr().redISub(one);
    const w = w2.redSqrt();
    const X = w.redSub(nr1);
    const X1 = one.redAdd(X);
    const YY = cm1.redMul(s).redMul(X).redMul(X1);
    const Y = YY.redMul(x.redMul(z));
    const X2 = X.redSqr().redIAdd(ci2);
    const Z = this.field(Y.redMul(X2).redJacobi());
    const u = Z.redMul(X);
    const tt = one.redSub(u);
    const tz = one.redAdd(u);
    const t = tz.isZero() ? tz : tt.redDiv(tz);

    if (t.redIsOdd() !== Boolean(sign))
      t.redINeg();

    return t;
  }

  _alt() {
    if (!this.alt)
      this.alt = this.toMont();

    return this.alt;
  }

  isElliptic() {
    const ad = this.a.redMul(this.d);
    const amd = this.a.redSub(this.d);

    // a * d * (a - d) != 0
    return !ad.redMul(amd).isZero();
  }

  jinv() {
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    const {a, d} = this;
    const ad = a.redMul(d);
    const amd4 = a.redSub(d).redPown(4);
    const a2 = a.redSqr();
    const d2 = d.redSqr();
    const t0 = a2.redAdd(ad.redMuln(14)).redIAdd(d2);
    const lhs = t0.redPown(3).redIMuln(16);
    const rhs = ad.redMul(amd4);

    if (rhs.isZero())
      throw new Error('Curve is not elliptic.');

    // 16 * (a^2 + 14 * a * d + d^2)^3 / (a * d * (a - d)^4)
    return lhs.redDiv(rhs).fromRed();
  }

  isComplete() {
    return this.a.redJacobi() === 1
        && this.d.redJacobi() === -1;
  }

  point(x, y, z, t) {
    return new EdwardsPoint(this, x, y, z, t);
  }

  jpoint(x, y, z) {
    assert(x == null && y == null && z == null);
    return this.point();
  }

  cpoint(xx, xz, yy, yz) {
    assert(xx instanceof BN);
    assert(xz instanceof BN);
    assert(yy instanceof BN);
    assert(yz instanceof BN);

    const x = xx.redMul(yz);
    const y = yy.redMul(xz);
    const z = xz.redMul(yz);
    const t = xx.redMul(yy);

    return this.point(x, y, z, t);
  }

  solveX2(y) {
    // [RFC8032] Section 5.1.3 & 5.2.3.
    assert(y instanceof BN);

    // x^2 = (y^2 - 1) / (d * y^2 - a)
    const y2 = y.redSqr();
    const rhs = this._mulD(y2).redISub(this.a);
    const lhs = y2.redISub(this.one);
    const x2 = lhs.redDiv(rhs);

    return x2;
  }

  solveX(y) {
    // Optimize with inverse square root trick.
    //
    // Note that `0 / 0` can only occur if
    // `a == d` (i.e. the curve is singular).
    const y2 = y.redSqr();
    const rhs = this._mulD(y2).redISub(this.a);
    const lhs = y2.redISub(this.one);

    return lhs.redDivSqrt(rhs);
  }

  solveY2(x) {
    assert(x instanceof BN);

    // y^2 = (a * x^2 - 1) / (d * x^2 - 1)
    const x2 = x.redSqr();
    const lhs = this._mulA(x2).redISub(this.one);
    const rhs = this._mulD(x2).redISub(this.one);
    const y2 = lhs.redDiv(rhs);

    return y2;
  }

  solveY(x) {
    // Optimize with inverse square root trick.
    //
    // Note that `0 / 0` can only occur if
    // `a == d` (i.e. the curve is singular).
    const x2 = x.redSqr();
    const lhs = this._mulA(x2).redISub(this.one);
    const rhs = this._mulD(x2).redISub(this.one);

    return lhs.redDivSqrt(rhs);
  }

  validate(point) {
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    //           Page 11, Section 6.
    assert(point instanceof EdwardsPoint);

    // Z1 = 1
    if (point.zOne) {
      // a * x^2 + y^2 = 1 + d * x^2 * y^2
      const x2 = point.x.redSqr();
      const y2 = point.y.redSqr();
      const dxy = this._mulD(x2).redMul(y2);
      const lhs = this._mulA(x2).redIAdd(y2);
      const rhs = this.one.redAdd(dxy);
      const tz = point.t;
      const xy = point.x.redMul(point.y);

      return lhs.eq(rhs) && tz.eq(xy);
    }

    // (a * x^2 + y^2) * z^2 = z^4 + d * x^2 * y^2
    const x2 = point.x.redSqr();
    const y2 = point.y.redSqr();
    const z2 = point.z.redSqr();
    const z4 = z2.redSqr();
    const dxy = this._mulD(x2).redMul(y2);
    const lhs = this._mulA(x2).redIAdd(y2).redMul(z2);
    const rhs = z4.redIAdd(dxy);
    const tz = point.t.redMul(point.z);
    const xy = point.x.redMul(point.y);

    return lhs.eq(rhs) && tz.eq(xy);
  }

  pointFromX(x, sign = null) {
    assert(x instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!x.red)
      x = x.toRed(this.red);

    const y = this.solveY(x);

    if (sign != null) {
      if (y.isZero() && sign)
        throw new Error('Invalid point.');

      if (y.redIsOdd() !== sign)
        y.redINeg();
    }

    return this.point(x, y);
  }

  pointFromY(y, sign = null) {
    assert(y instanceof BN);
    assert(sign == null || typeof sign === 'boolean');

    if (!y.red)
      y = y.toRed(this.red);

    const x = this.solveX(y);

    if (sign != null) {
      if (x.isZero() && sign)
        throw new Error('Invalid point.');

      if (x.redIsOdd() !== sign)
        x.redINeg();
    }

    return this.point(x, y);
  }

  isIsomorphic(curve, invert = false) {
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    //           Definition 2.1, Page 3, Section 2.
    assert(curve instanceof Curve);
    assert(typeof invert === 'boolean');

    if (!curve.p.eq(this.p))
      return false;

    // E(a,d) <-> E(a,b)
    if (curve.type === 'short')
      return curve.isIsomorphic(this);

    // E(a,d) <-> M(A,B)
    // E(a,d) <-> M(-A,-B)
    if (curve.type === 'mont') {
      // A * (a - d) = 2 * (a + d)
      const a = this.field(curve.a);

      let apd, amd;

      if (invert) {
        apd = this.d.redAdd(this.a);
        amd = this.d.redSub(this.a);
      } else {
        apd = this.a.redAdd(this.d);
        amd = this.a.redSub(this.d);
      }

      return a.redMul(amd).eq(apd.redIMuln(2));
    }

    // E(a,d) <-> E(a',a'd/a)
    if (curve.type === 'edwards') {
      // a' * d = a * d'
      const a = this.field(curve.a);
      const d = this.field(curve.d);

      return this.a.redMul(d).eq(a.redMul(this.d));
    }

    return false;
  }

  isIsogenous(curve) {
    // Check for the 4-isogenies described by Hamburg:
    // https://moderncrypto.org/mail-archive/curves/2016/000806.html
    assert(curve instanceof Curve);

    if (!curve.p.eq(this.p))
      return false;

    // E(1,d) <-> M(2-4d,1)
    if (curve.type === 'mont') {
      if (!this.a.eq(this.one))
        return false;

      const a = this.field(curve.a);
      const b = this.field(curve.b);
      const d24 = this.two.redSub(this.d.redMuln(4));

      return a.eq(d24) && b.eq(this.one);
    }

    // E(a,d) <-> E(-a,d-a)
    if (curve.type === 'edwards') {
      const a = this.field(curve.a);
      const d = this.field(curve.d);

      return a.eq(this.a.redNeg())
          && d.eq(this.d.redSub(this.a));
    }

    return false;
  }

  pointFromShort(point) {
    // [TWISTEQ] Section 1.
    assert(point instanceof ShortPoint);

    if (this.isIsomorphic(point.curve)) {
      // Equivalence for E(a,b)->E(a',d'):
      //
      //   x' = (6 * x - a' - d') / (6 * y)
      //   y' = (12 * x - 5 * a' + d') / (12 * x + a' - 5 * d')
      //
      // Undefined for x = (5 * d' - a') / 12 or y = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - ((a' + d') / 6, 0) -> (0, -1)
      //   - ((5 * d' - a') / 12, (d' - a') / 4 * sqrt(d')) -> (sqrt(1/d'), oo)
      //
      // Unexceptional Cases:
      //   - ((5 * a' - d') / 12, (a' - d') / 4 * sqrt(a')) -> (sqrt(1/a'), 0)
      if (point.isInfinity())
        return this.point();

      if (point.y.isZero())
        return this.point(this.zero, this.one.redNeg());

      const {a, d} = this;
      const [u2, u3] = this._scale(point.curve);
      const a5 = a.redMuln(5);
      const d5 = d.redMuln(5);
      const x = this.field(point.x).redMul(u2);
      const y = this.field(point.y).redMul(u3);
      const x6 = x.redMuln(6);
      const x12 = x.redMuln(12);
      const xx = x6.redSub(a).redISub(d);
      const xz = y.redMuln(6);
      const yy = x12.redSub(a5).redIAdd(d);
      const yz = x12.redAdd(a).redISub(d5);

      return this.cpoint(xx, xz, yy, yz);
    }

    throw new Error('Not implemented.');
  }

  pointFromMont(point) {
    // [RFC7748] Section 4.1 & 4.2.
    // [MONT3] Page 6, Section 2.5.
    // [TWISTED] Theorem 3.2, Page 4, Section 3.
    assert(point instanceof MontPoint);
    assert(point.curve.p.eq(this.p));

    // Montgomery `u`, `v`.
    const u = this.field(point.x);
    const v = this.field(point.y);

    if (this.isIsogenous(point.curve)) {
      // 4-isogeny maps for M(2-4d,1)->E(1,d):
      //
      //   x = 4 * v * (u^2 - 1) / (u^4 - 2 * u^2 + 4 * v^2 + 1)
      //   y = -(u^5 - 2 * u^3 - 4 * u * v^2 + u) /
      //        (u^5 - 2 * u^2 * v^2 - 2 * u^3 - 2 * v^2 + u)
      //
      // Undefined for u = 0 and v = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - (0, 0) -> (0, 1)
      //
      // Unexceptional Cases:
      //   - (-1, +-sqrt(A - 2)) -> (0, 1)
      //   - (1, +-sqrt(A + 2)) -> (0, -1)
      //
      // The point (1, v) is invalid on Curve448.
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point();

      const u2 = u.redSqr();
      const u3 = u2.redMul(u);
      const u4 = u3.redMul(u);
      const u5 = u4.redMul(u);
      const v2 = v.redSqr();
      const a = v.redMuln(4);
      const b = u2.redSub(this.one);
      const c = u2.redMuln(2);
      const d = v2.redMuln(4);
      const e = u3.redIMuln(2);
      const f = u.redMul(v2).redIMuln(4);
      const g = u2.redMul(v2).redIMuln(2);
      const h = v2.redIMuln(2);
      const xx = a.redMul(b);
      const xz = u4.redISub(c).redIAdd(d).redIAdd(this.one);
      const yy = u5.redSub(e).redISub(f).redIAdd(u).redINeg();
      const yz = u5.redISub(g).redISub(e).redISub(h).redIAdd(u);

      return this.cpoint(xx, xz, yy, yz).divn(4);
    }

    if (this.isIsomorphic(point.curve, true)) {
      // Isomorphic maps for M(-A,-B)->E(a,d):
      //
      //   x = +-sqrt((A - 2) / (B * a)) * u / v
      //   y = (u + 1) / (u - 1)
      //
      // Undefined for u = 1 or v = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - (0, 0) -> (0, -1)
      //   - (1, +-sqrt((A + 2) / B)) -> (+-sqrt(1 / d), oo)
      //
      // Unexceptional Cases:
      //   - (-1, +-sqrt((A - 2) / B)) -> (+-sqrt(1 / a), 0)
      //
      // The point (1, v) is invalid on Curve448.
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.one.redNeg());

      const c = this._scale(point.curve, true);
      const xx = c.redMul(u);
      const xz = v;
      const yy = u.redAdd(this.one);
      const yz = u.redSub(this.one);

      return this.cpoint(xx, xz, yy, yz);
    }

    if (this.isIsomorphic(point.curve, false)) {
      // Isomorphic maps for M(A,B)->E(a,d):
      //
      //   x = +-sqrt((A + 2) / (B * a)) * u / v
      //   y = (u - 1) / (u + 1)
      //
      // Undefined for u = -1 or v = 0.
      //
      // Exceptional Cases:
      //   - O -> (0, 1)
      //   - (0, 0) -> (0, -1)
      //   - (-1, +-sqrt((A - 2) / B)) -> (+-sqrt(1 / d), oo)
      //
      // Unexceptional Cases:
      //   - (1, +-sqrt((A + 2) / B)) -> (+-sqrt(1 / a), 0)
      //
      // The point (-1, v) is invalid on Curve25519.
      if (point.isInfinity())
        return this.point();

      if (point.x.isZero())
        return this.point(this.zero, this.one.redNeg());

      const c = this._scale(point.curve, false);
      const xx = c.redMul(u);
      const xz = v;
      const yy = u.redSub(this.one);
      const yz = u.redAdd(this.one);

      return this.cpoint(xx, xz, yy, yz);
    }

    throw new Error('Not implemented.');
  }

  pointFromEdwards(point) {
    // [TWISTED] Definition 2.1, Page 3, Section 2.
    // [ISOGENY] Page 2, Section 2.
    assert(point instanceof EdwardsPoint);
    assert(point.curve.p.eq(this.p));

    // Edwards `x`, `y`, `z`, `t`.
    const a = this.field(point.curve.a);
    const x = this.field(point.x);
    const y = this.field(point.y);
    const z = this.field(point.z);
    const t = this.field(point.t);

    if (this.isIsogenous(point.curve)) {
      // 4-isogeny maps for E(a,d)<->E(-a,d-a):
      //
      //   x' = (2 * x * y) / (y^2 - a * x^2)
      //   y' = (y^2 + a * x^2) / (2 - y^2 - a * x^2)
      //
      // Undefined for y^2 - a * x^2 = 0
      //            or y^2 + a * x^2 = 2.
      const xy = x.redMul(y);
      const x2 = x.redSqr();
      const y2 = y.redSqr();
      const z2 = z.redSqr();
      const ax2 = a.redMul(x2);
      const xx = xy.redIMuln(2);
      const xz = y2.redSub(ax2);
      const yy = y2.redAdd(ax2);
      const yz = z2.redIMuln(2).redISub(yy);
      const p = this.cpoint(xx, xz, yy, yz);

      return !this.twisted ? p.divn(4) : p;
    }

    if (this.isIsomorphic(point.curve)) {
      // Isomorphic maps for E(a,d)<->E(a',a'd/a):
      //
      //   x' = +-sqrt(a / a') * x
      //   y' = y
      //
      // Undefined when (a / a') is not square.
      const c = this._scale(point.curve);
      const nx = c.redMul(x);
      const ny = y;
      const nz = z;
      const nt = c.redMul(t);

      return this.point(nx, ny, nz, nt);
    }

    throw new Error('Not implemented.');
  }

  pointFromUniform(u, curve = null) {
    assert(u instanceof BN);
    assert(u.red === this.red);
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    const u0 = curve.field(u);
    const p0 = curve.pointFromUniform(u0);

    return this.pointFromMont(p0);
  }

  pointToUniform(p, hint, curve = null) {
    // Convert an edwards point to a field
    // element by inverting the elligator2 map.
    //
    // Hint Layout:
    //
    //   [00000000] [0000] [0000]
    //        |        |      |
    //        |        |      +-- preimage index
    //        |        +--- subgroup
    //        +-- bits to OR with uniform bytes
    assert(p instanceof EdwardsPoint);
    assert((hint >>> 0) === hint);
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    // Add a random torsion component.
    const i = ((hint >> 4) & 15) % this.torsion.length;
    const q = p.add(this.torsion[i]);

    // Convert and invert.
    const p0 = curve.pointFromEdwards(q);
    const u0 = curve.pointToUniform(p0, hint & 15);

    return this.field(u0);
  }

  pointFromHash(bytes, pake, curve = null) {
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    const p0 = curve.pointFromHash(bytes, pake);

    return this.pointFromMont(p0);
  }

  pointToHash(p, subgroup, rng, curve = null) {
    assert(p instanceof EdwardsPoint);
    assert((subgroup >>> 0) === subgroup);
    assert(curve == null || (curve instanceof MontCurve));

    if (!curve)
      curve = this._alt();

    // Add a random torsion component.
    const i = subgroup % this.torsion.length;
    const q = p.add(this.torsion[i]);

    // Convert and invert.
    const p0 = curve.pointFromEdwards(q);

    return curve.pointToHash(p0, 0, rng);
  }

  decodePoint(bytes) {
    return EdwardsPoint.decode(this, bytes);
  }

  toShort(a0, odd, sign = null) {
    const [a, b] = this._short(a0, odd);

    const curve = new ShortCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h
    });

    if (sign != null) {
      const [, u3] = curve._scale(this);

      if (u3.redIsOdd() !== sign)
        u3.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromEdwards(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromEdwards(this.torsion[i]);

    return curve;
  }

  toMont(b0, invert, sign = null) {
    const [a, b] = this._mont(b0, invert);

    const curve = new MontCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      b: b,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = this._scale(curve, invert);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity())
      curve.g = curve.pointFromEdwards(this.g);

    for (let i = 0; i < this.h.word(0); i++)
      curve.torsion[i] = curve.pointFromEdwards(this.torsion[i]);

    return curve;
  }

  toEdwards(a0, sign = null) {
    const [a, d] = this._edwards(a0);

    const curve = new EdwardsCurve({
      red: this.red,
      prime: this.prime,
      p: this.p,
      a: a,
      d: d,
      n: this.n,
      h: this.h,
      z: this.z
    });

    if (sign != null) {
      const c = curve._scale(this);

      if (c.redIsOdd() !== sign)
        c.redINeg();
    }

    if (!this.g.isInfinity()) {
      curve.g = curve.pointFromEdwards(this.g);
      curve.g.normalize();
    }

    if (curve.isComplete()) {
      for (let i = 0; i < this.h.word(0); i++) {
        curve.torsion[i] = curve.pointFromEdwards(this.torsion[i]);
        curve.torsion[i].normalize();
      }
    }

    return curve;
  }

  pointFromJSON(json) {
    return EdwardsPoint.fromJSON(this, json);
  }

  toJSON(pre) {
    const json = super.toJSON(pre);

    json.a = this.a.fromRed().toJSON();
    json.d = this.d.fromRed().toJSON();

    if (!this.s.isZero())
      json.s = this.s.fromRed().toJSON();

    return json;
  }
}

/**
 * EdwardsPoint
 */

class EdwardsPoint extends Point {
  constructor(curve, x, y, z, t) {
    assert(curve instanceof EdwardsCurve);

    super(curve, types.EXTENDED);

    this.x = this.curve.zero;
    this.y = this.curve.one;
    this.z = this.curve.one;
    this.t = this.curve.zero;
    this.zOne = true;

    if (x != null)
      this._init(x, y, z, t);
  }

  _init(x, y, z, t) {
    assert(x instanceof BN);
    assert(y instanceof BN);
    assert(z == null || (z instanceof BN));
    assert(t == null || (t instanceof BN));

    this.x = x;
    this.y = y;
    this.z = z || this.curve.one;
    this.t = t || null;

    if (!this.x.red)
      this.x = this.x.toRed(this.curve.red);

    if (!this.y.red)
      this.y = this.y.toRed(this.curve.red);

    if (!this.z.red)
      this.z = this.z.toRed(this.curve.red);

    if (this.t && !this.t.red)
      this.t = this.t.toRed(this.curve.red);

    this.zOne = this.z.eq(this.curve.one);

    this._check();

    if (!this.t) {
      this.t = this.x.redMul(this.y);
      if (!this.zOne)
        this.t = this.t.redDiv(this.z);
    }
  }

  _check() {
    // In order to achieve complete
    // addition formulas, `a` must
    // be a square (always the case
    // for a=1), and `d` must be a
    // non-square.
    //
    // If this is not the case, the
    // addition formulas may have
    // exceptional cases where Z3=0.
    //
    // In particular, this can occur
    // when: Q*h = -P*h and Q != -P.
    //
    // This is assuming 4-torsion is
    // involved (the 4-torsion point
    // is _not_ representable when
    // `d` is square).
    if (this.z.isZero())
      throw new Error('Invalid point.');
  }

  clone() {
    return this.curve.point(this.x, this.y, this.z, this.t);
  }

  normalize() {
    // https://hyperelliptic.org/EFD/g1p/auto-edwards-projective.html#scaling-z
    // 1I + 2M (+ 1M if extended)

    // Z1 = 1
    if (this.zOne)
      return this;

    // A = 1 / Z1
    const a = this.z.redInvert();

    // X3 = X1 * A
    this.x = this.x.redMul(a);

    // Y3 = Y1 * A
    this.y = this.y.redMul(a);

    // T3 = T1 * A
    this.t = this.t.redMul(a);

    // Z3 = 1
    this.z = this.curve.one;
    this.zOne = true;

    return this;
  }

  scale(a) {
    assert(a instanceof BN);

    // X3 = X1 * A
    const nx = this.x.redMul(a);

    // Y3 = Y1 * A
    const ny = this.y.redMul(a);

    // Z3 = Z1 * A
    const nz = this.z.redMul(a);

    // T3 = T1 * A
    const nt = this.t.redMul(a);

    return this.curve.point(nx, ny, nz, nt);
  }

  neg() {
    // -(X1, Y1, Z1, T1) = (-X1, Y1, Z1, -T1)
    const nx = this.x.redNeg();
    const ny = this.y;
    const nz = this.z;
    const nt = this.t.redNeg();

    return this.curve.point(nx, ny, nz, nt);
  }

  add(p) {
    assert(p instanceof EdwardsPoint);

    // P = O
    if (this.isInfinity())
      return p;

    // Q = O
    if (p.isInfinity())
      return this;

    // Z1 = 1
    if (this.zOne)
      return p._add(this);

    return this._add(p);
  }

  _add(p) {
    // a = -1
    if (this.curve.mOneA)
      return this._addM1(p);

    return this._addA(p);
  }

  _addM1(p) {
    // Assumes a = -1.
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
    // 8M + 8A + 1*k + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-madd-2008-hwcd-3
    // 7M + 8A + 1*k + 1*2

    // A = (Y1 - X1) * (Y2 - X2)
    const a = this.y.redSub(this.x).redMul(p.y.redSub(p.x));

    // B = (Y1 + X1) * (Y2 + X2)
    const b = this.y.redAdd(this.x).redMul(p.y.redAdd(p.x));

    // C = T1 * k * T2
    const c = this.t.redMul(this.curve.k).redMul(p.t);

    // D = Z1 * 2 * Z2
    const d = p.zOne ? this.z.redAdd(this.z) : this.z.redMul(p.z).redIMuln(2);

    // E = B - A
    const e = b.redSub(a);

    // F = D - C
    const f = d.redSub(c);

    // G = D + C
    const g = d.redIAdd(c);

    // H = B + A
    const h = b.redIAdd(a);

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  _addA(p) {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    // 9M + 7A + 1*a + 1*d
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-madd-2008-hwcd
    // 8M + 7A + 1*a + 1*d

    // A = X1 * X2
    const a = this.x.redMul(p.x);

    // B = Y1 * Y2
    const b = this.y.redMul(p.y);

    // C = T1 * d * T2
    const c = this.curve._mulD(this.t).redMul(p.t);

    // D = Z1 * Z2
    const d = p.zOne ? this.z.clone() : this.z.redMul(p.z);

    // + XYXY = (X1 + Y1) * (X2 + Y2)
    const xyxy = this.x.redAdd(this.y).redMul(p.x.redAdd(p.y));

    // E = (X1 + Y1) * (X2 + Y2) - A - B
    const e = xyxy.redISub(a).redISub(b);

    // F = D - C
    const f = d.redSub(c);

    // G = D + C
    const g = d.redIAdd(c);

    // H = B - a * A
    const h = b.redISub(this.curve._mulA(a));

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  dbl() {
    // P = O
    if (this.isInfinity())
      return this;

    return this._dbl();
  }

  _dbl() {
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    // 4M + 4S + 6A + 1*a + 1*2
    //
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-mdbl-2008-hwcd
    // 3M + 4S + 7A + 1*a + 1*2

    // A = X1^2
    const a = this.x.redSqr();

    // B = Y1^2
    const b = this.y.redSqr();

    // C = 2 * Z1^2
    const c = this.zOne ? this.curve.two : this.z.redSqr().redIMuln(2);

    // D = a * A
    const d = this.curve._mulA(a);

    // E = (X1 + Y1)^2 - A - B
    const e = this.x.redAdd(this.y).redSqr().redISub(a).redISub(b);

    // G = D + B
    const g = d.redAdd(b);

    // F = G - C
    const f = g.redSub(c);

    // H = D - B
    const h = d.redISub(b);

    // X3 = E * F
    const nx = e.redMul(f);

    // Y3 = G * H
    const ny = g.redMul(h);

    // T3 = E * H
    const nt = e.redMul(h);

    // Z3 = F * G
    const nz = f.redMul(g);

    return this.curve.point(nx, ny, nz, nt);
  }

  getX() {
    this.normalize();
    return this.x.fromRed();
  }

  getY() {
    this.normalize();
    return this.y.fromRed();
  }

  eq(p) {
    assert(p instanceof EdwardsPoint);
    assert(!this.z.isZero());
    assert(!p.z.isZero());

    // P = Q
    if (this === p)
      return true;

    // Z1 = Z2
    if (this.z.eq(p.z)) {
      return this.x.eq(p.x)
          && this.y.eq(p.y);
    }

    // X1 * Z2 = X2 * Z1
    const x1 = this.x.redMul(p.z);
    const x2 = p.x.redMul(this.z);

    if (!x1.eq(x2))
      return false;

    const y1 = this.y.redMul(p.z);
    const y2 = p.y.redMul(this.z);

    return y1.eq(y2);
  }

  cmp(point) {
    assert(point instanceof EdwardsPoint);

    return this.order().cmp(point.order())
        || this.getY().cmp(point.getY())
        || this.getX().cmp(point.getX());
  }

  isInfinity() {
    assert(!this.z.isZero());

    // X1 = 0
    if (!this.x.isZero())
      return false;

    // Y1 = Z1
    return this.y.eq(this.z);
  }

  isOrder2() {
    if (this.isInfinity())
      return false;

    return this.x.isZero();
  }

  isOdd() {
    this.normalize();
    return this.x.redIsOdd();
  }

  isEven() {
    this.normalize();
    return this.x.redIsEven();
  }

  toP() {
    return this.normalize();
  }

  toJ() {
    return this;
  }

  encode() {
    // [RFC8032] Section 5.1.2.
    const y = this.getY();

    // Note: `x` normalized from `getY()` call.
    y.setn(this.curve.signBit, this.x.redIsOdd());

    return this.curve.encodeAdjusted(y);
  }

  static decode(curve, bytes) {
    // [RFC8032] Section 5.1.3.
    assert(curve instanceof EdwardsCurve);

    const y = curve.decodeAdjusted(bytes);
    const sign = y.testn(curve.signBit) !== 0;

    y.setn(curve.signBit, 0);

    if (y.cmp(curve.p) >= 0)
      throw new Error('Invalid point.');

    return curve.pointFromY(y, sign);
  }

  toJSON(pre) {
    if (this.isInfinity())
      return [];

    const x = this.getX().toJSON();
    const y = this.getY().toJSON();

    if (pre === true && this.pre)
      return [x, y, this.pre.toJSON()];

    return [x, y];
  }

  toPretty() {
    const size = this.curve.fieldSize * 2;
    const x = toPretty(this.getX(), size);
    const y = toPretty(this.getY(), size);

    return [x, y];
  }

  static fromJSON(curve, json) {
    assert(curve instanceof EdwardsCurve);
    assert(Array.isArray(json));
    assert(json.length === 0
        || json.length === 2
        || json.length === 3);

    if (json.length === 0)
      return curve.point();

    const x = BN.fromJSON(json[0]);
    const y = BN.fromJSON(json[1]);
    const point = curve.point(x, y);

    if (json.length > 2 && json[2] != null)
      point.pre = Precomp.fromJSON(point, json[2]);

    return point;
  }

  [custom]() {
    if (this.isInfinity())
      return '<EdwardsPoint: Infinity>';

    return '<EdwardsPoint:'
        + ' x=' + this.x.fromRed().toString(16, 2)
        + ' y=' + this.y.fromRed().toString(16, 2)
        + ' z=' + this.z.fromRed().toString(16, 2)
        + '>';
  }
}

/**
 * Precomp
 */

class Precomp {
  constructor() {
    this.naf = null;
    this.windows = null;
    this.doubles = null;
    this.blinding = null;
    this.beta = null;
  }

  map(func) {
    assert(typeof func === 'function');

    const out = new this.constructor();

    if (this.naf)
      out.naf = this.naf.map(func);

    if (this.doubles)
      out.doubles = this.doubles.map(func);

    return out;
  }

  toJSON() {
    return {
      naf: this.naf ? this.naf.toJSON() : null,
      windows: this.windows ? this.windows.toJSON() : null,
      doubles: this.doubles ? this.doubles.toJSON() : null,
      blinding: this.blinding ? this.blinding.toJSON() : undefined
    };
  }

  fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');

    if (json.naf != null)
      this.naf = NAF.fromJSON(point, json.naf);

    if (json.windows != null)
      this.windows = Windows.fromJSON(point, json.windows);

    if (json.doubles != null)
      this.doubles = Doubles.fromJSON(point, json.doubles);

    if (json.blinding != null)
      this.blinding = Blinding.fromJSON(point, json.blinding);

    return this;
  }

  static fromJSON(point, json) {
    return new this().fromJSON(point, json);
  }
}

/**
 * NAF
 */

class NAF {
  constructor(width, points) {
    this.width = width;
    this.points = points;
  }

  map(func) {
    assert(typeof func === 'function');

    const {width} = this;
    const points = [];

    for (const point of this.points)
      points.push(func(point));

    return new this.constructor(width, points);
  }

  toJSON() {
    return {
      width: this.width,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.width >>> 0) === json.width);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {width} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(width, points);
  }
}

/**
 * Windows
 */

class Windows {
  constructor(width, bits, points) {
    this.width = width;
    this.bits = bits;
    this.points = points;
  }

  toJSON() {
    return {
      width: this.width,
      bits: this.bits,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.width >>> 0) === json.width);
    assert((json.bits >>> 0) === json.bits);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {width, bits} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(width, bits, points);
  }
}

/**
 * Doubles
 */

class Doubles {
  constructor(step, points) {
    this.step = step;
    this.points = points;
  }

  map(func) {
    assert(typeof func === 'function');

    const {step} = this;
    const points = [];

    for (const point of this.points)
      points.push(func(point));

    return new this.constructor(step, points);
  }

  toJSON() {
    return {
      step: this.step,
      points: this.points.slice(1).map((point) => {
        return point.toJSON();
      })
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');
    assert((json.step >>> 0) === json.step);
    assert(Array.isArray(json.points));

    const {curve} = point;
    const {step} = json;
    const points = [point];

    for (const item of json.points)
      points.push(curve.pointFromJSON(item));

    return new this(step, points);
  }
}

/**
 * Blinding
 */

class Blinding {
  constructor(blind, unblind) {
    this.blind = blind;
    this.unblind = unblind;
  }

  toJSON() {
    return {
      blind: this.blind.toJSON(),
      unblind: this.unblind.toJSON()
    };
  }

  static fromJSON(point, json) {
    assert(point instanceof Point);
    assert(json && typeof json === 'object');

    const {curve} = point;
    const blind = BN.fromJSON(json.blind);
    const unblind = curve.pointFromJSON(json.unblind);

    return new this(blind, unblind);
  }
}

/**
 * Endo
 */

class Endo {
  constructor(beta, lambda, basis, pre) {
    this.beta = beta;
    this.lambda = lambda;
    this.basis = basis;
    this.pre = pre;
  }

  toJSON() {
    return {
      beta: this.beta.fromRed().toJSON(),
      lambda: this.lambda.toJSON(),
      basis: [
        this.basis[0].toJSON(),
        this.basis[1].toJSON()
      ],
      pre: [
        this.pre[0],
        this.pre[1].toJSON(),
        this.pre[2].toJSON()
      ]
    };
  }

  static fromJSON(curve, json) {
    assert(curve instanceof Curve);
    assert(json && typeof json === 'object');
    assert(Array.isArray(json.basis));
    assert(Array.isArray(json.pre));
    assert(json.basis.length === 2);
    assert(json.pre.length === 3);
    assert((json.pre[0] >>> 0) === json.pre[0]);

    const beta = BN.fromJSON(json.beta).toRed(curve.red);
    const lambda = BN.fromJSON(json.lambda);

    const basis = [
      Vector.fromJSON(json.basis[0]),
      Vector.fromJSON(json.basis[1])
    ];

    const pre = [
      json.pre[0],
      BN.fromJSON(json.pre[1]),
      BN.fromJSON(json.pre[2])
    ];

    return new this(beta, lambda, basis, pre);
  }
}

/**
 * Vector
 */

class Vector {
  constructor(a, b) {
    this.a = a;
    this.b = b;
  }

  toJSON() {
    return {
      a: this.a.toJSON(),
      b: this.b.toJSON()
    };
  }

  static fromJSON(json) {
    assert(json && typeof json === 'object');

    const a = BN.fromJSON(json.a);
    const b = BN.fromJSON(json.b);

    return new this(a, b);
  }
}

/**
 * P192
 * https://tinyurl.com/fips-186-2 (page 29)
 * https://tinyurl.com/fips-186-3 (page 88)
 */

class P192 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P192',
      ossl: 'prime192v1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p192',
      // 2^192 - 2^64 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff fffffffe',
          'ffffffff ffffffff'],
      // -3 mod p
      a: ['ffffffff ffffffff ffffffff fffffffe',
          'ffffffff fffffffc'],
      b: ['64210519 e59c80e7 0fa7e9ab 72243049',
          'feb8deec c146b9b1'],
      n: ['ffffffff ffffffff ffffffff 99def836',
          '146bc9b1 b4d22831'],
      h: '1',
      // Icart
      z: '-5',
      g: [
        ['188da80e b03090f6 7cbf20eb 43a18800',
         'f4ff0afd 82ff1012'],
        ['07192b95 ffc8da78 631011ed 6b24cdd5',
         '73f977a1 1e794811'],
        pre
      ]
    });
  }
}

/**
 * P224
 * https://tinyurl.com/fips-186-2 (page 30)
 * https://tinyurl.com/fips-186-3 (page 88)
 */

class P224 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P224',
      ossl: 'secp224r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'p224',
      // 2^224 - 2^96 + 1 (1 mod 16)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          '00000000 00000000 00000001'],
      // -3 mod p
      a: ['ffffffff ffffffff ffffffff fffffffe',
          'ffffffff ffffffff fffffffe'],
      b: ['b4050a85 0c04b3ab f5413256 5044b0b7',
          'd7bfd8ba 270b3943 2355ffb4'],
      n: ['ffffffff ffffffff ffffffff ffff16a2',
          'e0b8f03e 13dd2945 5c5c2a3d'],
      h: '1',
      // SSWU
      z: '1f',
      g: [
        ['b70e0cbd 6bb4bf7f 321390b9 4a03c1d3',
         '56c21122 343280d6 115c1d21'],
        ['bd376388 b5f723fb 4c22dfe6 cd4375a0',
         '5a074764 44d58199 85007e34'],
        pre
      ]
    });
  }
}

/**
 * P256
 * https://tinyurl.com/fips-186-2 (page 31)
 * https://tinyurl.com/fips-186-3 (page 89)
 */

class P256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P256',
      ossl: 'prime256v1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // 2^256 - 2^224 + 2^192 + 2^96 - 1 (= 3 mod 4)
      p: ['ffffffff 00000001 00000000 00000000',
          '00000000 ffffffff ffffffff ffffffff'],
      // -3 mod p
      a: ['ffffffff 00000001 00000000 00000000',
          '00000000 ffffffff ffffffff fffffffc'],
      b: ['5ac635d8 aa3a93e7 b3ebbd55 769886bc',
          '651d06b0 cc53b0f6 3bce3c3e 27d2604b'],
      n: ['ffffffff 00000000 ffffffff ffffffff',
          'bce6faad a7179e84 f3b9cac2 fc632551'],
      h: '1',
      // SSWU
      z: '-a',
      g: [
        ['6b17d1f2 e12c4247 f8bce6e5 63a440f2',
         '77037d81 2deb33a0 f4a13945 d898c296'],
        ['4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16',
         '2bce3357 6b315ece cbb64068 37bf51f5'],
        pre
      ]
    });
  }
}

/**
 * P384
 * https://tinyurl.com/fips-186-2 (page 32)
 * https://tinyurl.com/fips-186-3 (page 89)
 */

class P384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P384',
      ossl: 'secp384r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prime: null,
      // 2^384 - 2^128 - 2^96 + 2^32 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffffe',
          'ffffffff 00000000 00000000 ffffffff'],
      // -3 mod p
      a: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff fffffffe',
          'ffffffff 00000000 00000000 fffffffc'],
      b: ['b3312fa7 e23ee7e4 988e056b e3f82d19',
          '181d9c6e fe814112 0314088f 5013875a',
          'c656398d 8a2ed19d 2a85c8ed d3ec2aef'],
      n: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff c7634d81 f4372ddf',
          '581a0db2 48b0a77a ecec196a ccc52973'],
      h: '1',
      // Icart
      z: '-c',
      g: [
        ['aa87ca22 be8b0537 8eb1c71e f320ad74',
         '6e1d3b62 8ba79b98 59f741e0 82542a38',
         '5502f25d bf55296c 3a545e38 72760ab7'],
        ['3617de4a 96262c6f 5d9e98bf 9292dc29',
         'f8f41dbd 289a147c e9da3113 b5f0b8c0',
         '0a60b1ce 1d7e819d 7a431d7c 90ea0e5f'],
        pre
      ]
    });
  }
}

/**
 * P521
 * https://tinyurl.com/fips-186-2 (page 33)
 * https://tinyurl.com/fips-186-3 (page 90)
 */

class P521 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'P521',
      ossl: 'secp521r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prime: 'p521',
      // 2^521 - 1 (= 3 mod 4)
      p: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff'],
      // -3 mod p
      a: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffffffc'],
      b: ['00000051 953eb961 8e1c9a1f 929a21a0',
          'b68540ee a2da725b 99b315f3 b8b48991',
          '8ef109e1 56193951 ec7e937b 1652c0bd',
          '3bb1bf07 3573df88 3d2c34f1 ef451fd4',
          '6b503f00'],
      n: ['000001ff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'fffffffa 51868783 bf2f966b 7fcc0148',
          'f709a5d0 3bb5c9b8 899c47ae bb6fb71e',
          '91386409'],
      h: '1',
      // SSWU
      z: '-4',
      g: [
        ['000000c6 858e06b7 0404e9cd 9e3ecb66',
         '2395b442 9c648139 053fb521 f828af60',
         '6b4d3dba a14b5e77 efe75928 fe1dc127',
         'a2ffa8de 3348b3c1 856a429b f97e7e31',
         'c2e5bd66'],
        ['00000118 39296a78 9a3bc004 5c8a5fb4',
         '2c7d1bd9 98f54449 579b4468 17afbd17',
         '273e662c 97ee7299 5ef42640 c550b901',
         '3fad0761 353c7086 a272c240 88be9476',
         '9fd16650'],
        pre
      ]
    });
  }
}

/**
 * SECP256K1
 * https://www.secg.org/SEC2-Ver-1.0.pdf (page 15, section 2.7.1)
 * https://www.secg.org/sec2-v2.pdf (page 9, section 2.4.1)
 */

class SECP256K1 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'SECP256K1',
      ossl: 'secp256k1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: 'k256',
      // 2^256 - 2^32 - 977 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe fffffc2f'],
      a: '0',
      b: '7',
      n: ['ffffffff ffffffff ffffffff fffffffe',
          'baaedce6 af48a03b bfd25e8c d0364141'],
      h: '1',
      // SVDW
      z: '1',
      // sqrt(-3)
      c: ['0a2d2ba9 3507f1df 233770c2 a797962c',
          'c61f6d15 da14ecd4 7d8d27ae 1cd5f852'],
      g: [
        ['79be667e f9dcbbac 55a06295 ce870b07',
         '029bfcdb 2dce28d9 59f2815b 16f81798'],
        ['483ada77 26a3c465 5da4fbfc 0e1108a8',
         'fd17b448 a6855419 9c47d08f fb10d4b8'],
        pre
      ],
      // Precomputed endomorphism.
      endo: {
        beta: ['7ae96a2b 657c0710 6e64479e ac3434e9',
               '9cf04975 12f58995 c1396c28 719501ee'],
        lambda: ['5363ad4c c05c30e0 a5261c02 8812645a',
                 '122e22ea 20816678 df02967c 1b23bd72'],
        basis: [
          {
            a: '3086d221a7d46bcde86c90e49284eb15',
            b: '-e4437ed6010e88286f547fa90abfe4c3'
          },
          {
            a: '114ca50f7a8e2f3f657c1108d9d44cfd8',
            b: '3086d221a7d46bcde86c90e49284eb15'
          }
        ],
        pre: [
          384,
          ['3086d221 a7d46bcd e86c90e4 9284eb15',
           '3daa8a14 71e8ca7f e893209a 45dbb031'],
          ['-',
           'e4437ed6 010e8828 6f547fa9 0abfe4c4',
           '221208ac 9df506c6 1571b4ae 8ac47f71']
        ]
      }
    });
  }
}

/**
 * BRAINPOOLP256
 * https://tools.ietf.org/html/rfc5639#section-3.4
 */

class BRAINPOOLP256 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP256',
      ossl: 'brainpoolP256r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA256',
      prime: null,
      // (= 3 mod 4)
      p: ['a9fb57db a1eea9bc 3e660a90 9d838d72',
          '6e3bf623 d5262028 2013481d 1f6e5377'],
      a: ['7d5a0975 fc2c3057 eef67530 417affe7',
          'fb8055c1 26dc5c6c e94a4b44 f330b5d9'],
      b: ['26dc5c6c e94a4b44 f330b5d9 bbd77cbf',
          '95841629 5cf7e1ce 6bccdc18 ff8c07b6'],
      n: ['a9fb57db a1eea9bc 3e660a90 9d838d71',
          '8c397aa3 b561a6f7 901e0e82 974856a7'],
      h: '1',
      // Icart
      z: '-2',
      g: [
        ['8bd2aeb9 cb7e57cb 2c4b482f fc81b7af',
         'b9de27e1 e3bd23c2 3a4453bd 9ace3262'],
        ['547ef835 c3dac4fd 97f8461a 14611dc9',
         'c2774513 2ded8e54 5c1d54c7 2f046997'],
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP384
 * https://tools.ietf.org/html/rfc5639#section-3.6
 */

class BRAINPOOLP384 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP384',
      ossl: 'brainpoolP384r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA384',
      prime: null,
      // (= 3 mod 4)
      p: ['8cb91e82 a3386d28 0f5d6f7e 50e641df',
          '152f7109 ed5456b4 12b1da19 7fb71123',
          'acd3a729 901d1a71 87470013 3107ec53'],
      a: ['7bc382c6 3d8c150c 3c72080a ce05afa0',
          'c2bea28e 4fb22787 139165ef ba91f90f',
          '8aa5814a 503ad4eb 04a8c7dd 22ce2826'],
      b: ['04a8c7dd 22ce2826 8b39b554 16f0447c',
          '2fb77de1 07dcd2a6 2e880ea5 3eeb62d5',
          '7cb43902 95dbc994 3ab78696 fa504c11'],
      n: ['8cb91e82 a3386d28 0f5d6f7e 50e641df',
          '152f7109 ed5456b3 1f166e6c ac0425a7',
          'cf3ab6af 6b7fc310 3b883202 e9046565'],
      h: '1',
      // SSWU
      z: '-5',
      g: [
        ['1d1c64f0 68cf45ff a2a63a81 b7c13f6b',
         '8847a3e7 7ef14fe3 db7fcafe 0cbd10e8',
         'e826e034 36d646aa ef87b2e2 47d4af1e'],
        ['8abe1d75 20f9c2a4 5cb1eb8e 95cfd552',
         '62b70b29 feec5864 e19c054f f9912928',
         '0e464621 77918111 42820341 263c5315'],
        pre
      ]
    });
  }
}

/**
 * BRAINPOOLP512
 * https://tools.ietf.org/html/rfc5639#section-3.7
 */

class BRAINPOOLP512 extends ShortCurve {
  constructor(pre) {
    super({
      id: 'BRAINPOOLP512',
      ossl: 'brainpoolP512r1',
      type: 'short',
      endian: 'be',
      hash: 'SHA512',
      prime: null,
      // (= 3 mod 4)
      p: ['aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07',
          'cb308db3 b3c9d20e d6639cca 70330871',
          '7d4d9b00 9bc66842 aecda12a e6a380e6',
          '2881ff2f 2d82c685 28aa6056 583a48f3'],
      a: ['7830a331 8b603b89 e2327145 ac234cc5',
          '94cbdd8d 3df91610 a83441ca ea9863bc',
          '2ded5d5a a8253aa1 0a2ef1c9 8b9ac8b5',
          '7f1117a7 2bf2c7b9 e7c1ac4d 77fc94ca'],
      b: ['3df91610 a83441ca ea9863bc 2ded5d5a',
          'a8253aa1 0a2ef1c9 8b9ac8b5 7f1117a7',
          '2bf2c7b9 e7c1ac4d 77fc94ca dc083e67',
          '984050b7 5ebae5dd 2809bd63 8016f723'],
      n: ['aadd9db8 dbe9c48b 3fd4e6ae 33c9fc07',
          'cb308db3 b3c9d20e d6639cca 70330870',
          '553e5c41 4ca92619 41866119 7fac1047',
          '1db1d381 085ddadd b5879682 9ca90069'],
      h: '1',
      // Icart
      z: '7',
      g: [
        ['81aee4bd d82ed964 5a21322e 9c4c6a93',
         '85ed9f70 b5d916c1 b43b62ee f4d0098e',
         'ff3b1f78 e2d0d48d 50d1687b 93b97d5f',
         '7c6d5047 406a5e68 8b352209 bcb9f822'],
        ['7dde385d 566332ec c0eabfa9 cf7822fd',
         'f209f700 24a57b1a a000c55b 881f8111',
         'b2dcde49 4a5f485e 5bca4bd8 8a2763ae',
         'd1ca2b2f a8f05406 78cd1e0f 3ad80892'],
        pre
      ]
    });
  }
}

/**
 * X25519
 * https://tools.ietf.org/html/rfc7748#section-4.1
 */

class X25519 extends MontCurve {
  constructor() {
    super({
      id: 'X25519',
      ossl: 'X25519',
      type: 'mont',
      endian: 'le',
      hash: 'SHA512',
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      // 486662
      a: '76d06',
      b: '1',
      n: ['10000000 00000000 00000000 00000000',
          '14def9de a2f79cd6 5812631a 5cf5d3ed'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000009'],
        // See: https://www.rfc-editor.org/errata/eid4730
        ['5f51e65e 475f794b 1fe122d3 88b72eb3',
         '6dc2b281 92839e4d d6163a5d 81312c14']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['6be4f497 f9a9c2af c21fa77a d7f4a6ef',
           '635a11c7 284a9363 e9a248ef 9c884415']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001'],
          ['141b0b68 06563d50 3de05885 280b5910',
           '9ca5ee38 d7b56c9c 165db710 6377bbd8']
        ],
        [
          ['57119fd0 dd4e22d8 868e1c58 c45c4404',
           '5bef839c 55b1d0b1 248c50a3 bc959c5f'],
          ['68c59389 3d458e64 31c6ca00 45fb5015',
           '20a44346 8eaa68dd 0f103842 048065b7']
        ],
        [
          ['57119fd0 dd4e22d8 868e1c58 c45c4404',
           '5bef839c 55b1d0b1 248c50a3 bc959c5f'],
          ['173a6c76 c2ba719b ce3935ff ba04afea',
           'df5bbcb9 71559722 f0efc7bd fb7f9a36']
        ],
        [
          ['00b8495f 16056286 fdb1329c eb8d09da',
           '6ac49ff1 fae35616 aeb8413b 7c7aebe0'],
          ['3931c129 569e83a5 29482c14 e628b457',
           '933bfc29 ed801b4d 68871483 92507b1a']
        ],
        [
          ['00b8495f 16056286 fdb1329c eb8d09da',
           '6ac49ff1 fae35616 aeb8413b 7c7aebe0'],
          ['46ce3ed6 a9617c5a d6b7d3eb 19d74ba8',
           '6cc403d6 127fe4b2 9778eb7c 6daf84d3']
        ]
      ]
    });
  }
}

/**
 * X448
 * https://tools.ietf.org/html/rfc7748#section-4.2
 */

class X448 extends MontCurve {
  constructor() {
    super({
      id: 'X448',
      ossl: 'X448',
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      // 156326
      a: '262a6',
      b: '1',
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000005'],
        ['7d235d12 95f5b1f6 6c98ab6e 58326fce',
         'cbae5d34 f55545d0 60f75dc2 8df3f6ed',
         'b8027e23 46430d21 1312c4b1 50677af7',
         '6fd7223d 457b5b1a']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['ba4d3a08 29b6112f 8812e51b a0bb2abe',
           'bc1cb08e b48e5569 36ba50fd d2e7d68a',
           'f8cb3216 0522425b 3f990812 abbe635a',
           'd37a21e1 7551b193']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['45b2c5f7 d649eed0 77ed1ae4 5f44d541',
           '43e34f71 4b71aa96 c945af01 2d182975',
           '0734cde9 faddbda4 c066f7ed 54419ca5',
           '2c85de1e 8aae4e6c']
        ]
      ]
    });
  }
}

/**
 * MONT448
 * Isomorphic to Ed448-Goldilocks.
 */

class MONT448 extends MontCurve {
  constructor() {
    super({
      id: 'MONT448',
      ossl: null,
      type: 'mont',
      endian: 'le',
      hash: 'SHAKE256',
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      // -78160 / -39082 mod p
      a: ['b2cf97d2 d43459a9 31ed36b1 fc4e3cb5',
          '5d93f8d2 22746997 60ccffc6 49961ed6',
          'c5b05fca c24864ed 6fb59697 931b78da',
          '84ddecd8 ca2b5cfb'],
      b: '1',
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['ac0d24cc c6c75cb0 eb71f81e 7a6edf51',
         '48e88aee 009a2a24 e795687e c28e125a',
         '3e6730a6 0d46367b aa7fe99d 152128dc',
         '41321bc7 7817f059'],
        ['5a4437f6 80c0d0db 9b061276 d5d0ffcc',
         'e786ff33 b6a53d30 98746425 82e66f09',
         '4433dae7 7244a6e2 6b11e905 7228f483',
         '556c41a5 913f55fe']
      ],
      torsion: [
        [],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['bec92fd0 6da2acf2 b4e261e8 7cef0d34',
           '22e75c18 3c589857 b71924e5 73c2f9ce',
           'e18da5f2 466e2f39 3c2eedf0 f105a60a',
           'b40c717d 4f1e1fd7']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['4136d02f 925d530d 4b1d9e17 8310f2cb',
           'dd18a3e7 c3a767a8 48e6db19 8c3d0631',
           '1e725a0d b991d0c6 c3d1120f 0efa59f5',
           '4bf38e82 b0e1e028']
        ]
      ]
    });
  }
}

/**
 * ED25519
 * https://tools.ietf.org/html/rfc8032#section-5.1
 */

class ED25519 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED25519',
      ossl: 'ED25519',
      type: 'edwards',
      endian: 'le',
      hash: 'SHA512',
      prefix: 'SigEd25519 no Ed25519 collisions',
      context: false,
      prime: 'p25519',
      // 2^255 - 19 (= 5 mod 8)
      p: ['7fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff ffffffed'],
      a: '-1',
      // -121665 / 121666 mod p
      d: ['52036cee 2b6ffe73 8cc74079 7779e898',
          '00700a4d 4141d8ab 75eb4dca 135978a3'],
      n: ['10000000 00000000 00000000 00000000',
          '14def9de a2f79cd6 5812631a 5cf5d3ed'],
      h: '8',
      // Elligator 2
      z: '2',
      g: [
        ['216936d3 cd6e53fe c0a4e231 fdd6dc5c',
         '692cc760 9525a7b2 c9562d60 8f25d51a'],
        // 4/5
        ['66666666 66666666 66666666 66666666',
         '66666666 66666666 66666666 66666658'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000'],
          ['7fffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff ffffffff ffffffec']
        ],
        [
          ['2b832480 4fc1df0b 2b4d0099 3dfbd7a7',
           '2f431806 ad2fe478 c4ee1b27 4a0ea0b0'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['547cdb7f b03e20f4 d4b2ff66 c2042858',
           'd0bce7f9 52d01b87 3b11e4d8 b5f15f3d'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000']
        ],
        [
          ['1fd5b9a0 06394a28 e9339932 38de4abb',
           '5c193c70 13e5e238 dea14646 c545d14a'],
          ['05fc536d 880238b1 3933c6d3 05acdfd5',
           'f098eff2 89f4c345 b027b2c2 8f95e826']
        ],
        [
          ['602a465f f9c6b5d7 16cc66cd c721b544',
           'a3e6c38f ec1a1dc7 215eb9b9 3aba2ea3'],
          ['05fc536d 880238b1 3933c6d3 05acdfd5',
           'f098eff2 89f4c345 b027b2c2 8f95e826']
        ],
        [
          ['1fd5b9a0 06394a28 e9339932 38de4abb',
           '5c193c70 13e5e238 dea14646 c545d14a'],
          ['7a03ac92 77fdc74e c6cc392c fa53202a',
           '0f67100d 760b3cba 4fd84d3d 706a17c7']
        ],
        [
          ['602a465f f9c6b5d7 16cc66cd c721b544',
           'a3e6c38f ec1a1dc7 215eb9b9 3aba2ea3'],
          ['7a03ac92 77fdc74e c6cc392c fa53202a',
           '0f67100d 760b3cba 4fd84d3d 706a17c7']
        ]
      ]
    });
  }
}

/**
 * ISO448
 * https://tools.ietf.org/html/rfc7748#section-4.2
 * https://git.zx2c4.com/goldilocks/tree/_aux/ristretto/ristretto.sage#n658
 */

class ISO448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ISO448',
      ossl: null,
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '1',
      // 39082 / 39081 mod p
      d: ['d78b4bdc 7f0daf19 f24f38c2 9373a2cc',
          'ad461572 42a50f37 809b1da3 412a12e7',
          '9ccc9c81 264cfe9a d0809970 58fb61c4',
          '243cc32d baa156b9'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['79a70b2b 70400553 ae7c9df4 16c792c6',
         '1128751a c9296924 0c25a07d 728bdc93',
         'e21f7787 ed697224 9de732f3 8496cd11',
         '69871309 3e9c04fc'],
        // Note: the RFC has this wrong.
        ['7fffffff ffffffff ffffffff ffffffff',
         'ffffffff ffffffff ffffffff 80000000',
         '00000000 00000000 00000000 00000000',
         '00000000 00000001'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ]
      ]
    });
  }
}

/**
 * ED448
 * https://tools.ietf.org/html/rfc8032#section-5.2
 */

class ED448 extends EdwardsCurve {
  constructor(pre) {
    super({
      id: 'ED448',
      ossl: 'ED448',
      type: 'edwards',
      endian: 'le',
      hash: 'SHAKE256',
      prefix: 'SigEd448',
      context: true,
      prime: 'p448',
      // 2^448 - 2^224 - 1 (= 3 mod 4)
      p: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff'],
      a: '1',
      // -39081 mod p
      d: ['ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff fffffffe ffffffff',
          'ffffffff ffffffff ffffffff ffffffff',
          'ffffffff ffff6756'],
      n: ['3fffffff ffffffff ffffffff ffffffff',
          'ffffffff ffffffff ffffffff 7cca23e9',
          'c44edb49 aed63690 216cc272 8dc58f55',
          '2378c292 ab5844f3'],
      h: '4',
      // Elligator 2
      z: '-1',
      g: [
        ['4f1970c6 6bed0ded 221d15a6 22bf36da',
         '9e146570 470f1767 ea6de324 a3d3a464',
         '12ae1af7 2ab66511 433b80e1 8b00938e',
         '2626a82b c70cc05e'],
        ['693f4671 6eb6bc24 88762037 56c9c762',
         '4bea7373 6ca39840 87789c1e 05a0c2d7',
         '3ad3ff1c e67c39c4 fdbd132c 4ed7c8ad',
         '9808795b f230fa14'],
        pre
      ],
      torsion: [
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000'],
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe']
        ],
        [
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000001'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ],
        [
          ['ffffffff ffffffff ffffffff ffffffff',
           'ffffffff ffffffff fffffffe ffffffff',
           'ffffffff ffffffff ffffffff ffffffff',
           'ffffffff fffffffe'],
          ['00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000 00000000 00000000',
           '00000000 00000000']
        ]
      ]
    });
  }
}

/*
 * Curve Registry
 */

const curves = {
  __proto__: null,
  P192,
  P224,
  P256,
  P384,
  P521,
  SECP256K1,
  BRAINPOOLP256,
  BRAINPOOLP384,
  BRAINPOOLP512,
  X25519,
  X448,
  MONT448,
  ED25519,
  ISO448,
  ED448
};

const cache = {
  __proto__: null,
  P192: null,
  P224: null,
  P256: null,
  P384: null,
  P521: null,
  SECP256K1: null,
  BRAINPOOLP256: null,
  BRAINPOOLP384: null,
  BRAINPOOLP512: null,
  X25519: null,
  X448: null,
  MONT448: null,
  ED25519: null,
  ISO448: null,
  ED448: null
};

function curve(name, ...args) {
  assert(typeof name === 'string');

  const key = name.toUpperCase();

  let curve = cache[key];

  if (!curve) {
    const Curve = curves[key];

    if (!Curve)
      throw new Error(`Curve not found: "${name}".`);

    curve = new Curve(...args);
    cache[key] = curve;
  }

  return curve;
}

function register(name, Curve) {
  assert(typeof name === 'string');
  assert(typeof Curve === 'function');

  const key = name.toUpperCase();

  if (curves[key])
    throw new Error(`Curve already registered: "${name}".`);

  curves[key] = Curve;
  cache[key] = null;
}

/*
 * Scalar Recoding
 */

function getNAF(k, width, max) {
  // Computing the width-w NAF of a positive integer.
  //
  // [GECC] Algorithm 3.35, Page 100, Section 3.3.
  //
  // The above document describes a rather abstract
  // method of recoding. The more optimal method
  // below was ported from libsecp256k1.
  assert(k instanceof BN);
  assert(!k.red);
  assert((width >>> 0) === width);
  assert((max >>> 0) === max);

  const naf = new Array(max);
  const bits = k.bitLength() + 1;
  const sign = k.sign() | 1;

  assert(bits <= max);

  for (let i = 0; i < max; i++)
    naf[i] = 0;

  let i = 0;
  let carry = 0;
  let word;

  while (i < bits) {
    if (k.bit(i) === carry) {
      i += 1;
      continue;
    }

    word = k.bits(i, width) + carry;
    carry = (word >> (width - 1)) & 1;
    word -= carry << width;

    naf[i] = sign * word;

    i += width;
  }

  assert(carry === 0);

  return naf;
}

function getFixedNAF(k, width, max, step) {
  assert((step >>> 0) === step);

  // Recode to NAF.
  const naf = getNAF(k, width, max);

  // Translate into more windowed form.
  const len = Math.ceil(naf.length / step);
  const repr = new Array(len);

  let i = 0;

  for (let j = 0; j < naf.length; j += step) {
    let nafW = 0;

    for (let k = j + step - 1; k >= j; k--)
      nafW = (nafW << 1) + naf[k];

    repr[i++] = nafW;
  }

  assert(i === len);

  return repr;
}

function getJSF(k1, k2, max) {
  // Joint sparse form.
  //
  // [GECC] Algorithm 3.50, Page 111, Section 3.3.
  assert(k1 instanceof BN);
  assert(k2 instanceof BN);
  assert(!k1.red);
  assert(!k2.red);
  assert((max >>> 0) === max);

  const jsf = [new Array(max), new Array(max)];
  const bits = Math.max(k1.bitLength(), k2.bitLength()) + 1;
  const s1 = k1.sign() | 1;
  const s2 = k2.sign() | 1;

  assert(bits <= max);

  let d1 = 0;
  let d2 = 0;

  for (let i = 0; i < bits; i++) {
    const b1 = k1.bits(i, 3);
    const b2 = k2.bits(i, 3);

    // First phase.
    let m14 = ((b1 & 3) + d1) & 3;
    let m24 = ((b2 & 3) + d2) & 3;
    let u1 = 0;
    let u2 = 0;

    if (m14 === 3)
      m14 = -1;

    if (m24 === 3)
      m24 = -1;

    if (m14 & 1) {
      const m8 = ((b1 & 7) + d1) & 7;

      if ((m8 === 3 || m8 === 5) && m24 === 2)
        u1 = -m14;
      else
        u1 = m14;
    }

    if (m24 & 1) {
      const m8 = ((b2 & 7) + d2) & 7;

      if ((m8 === 3 || m8 === 5) && m14 === 2)
        u2 = -m24;
      else
        u2 = m24;
    }

    jsf[0][i] = u1 * s1;
    jsf[1][i] = u2 * s2;

    // Second phase.
    if (2 * d1 === 1 + u1)
      d1 = 1 - d1;

    if (2 * d2 === 1 + u2)
      d2 = 1 - d2;
  }

  for (let i = bits; i < max; i++) {
    jsf[0][i] = 0;
    jsf[1][i] = 0;
  }

  return jsf;
}

function getJNAF(c1, c2, max) {
  const jsf = getJSF(c1, c2, max);
  const naf = new Array(max);

  // JSF -> NAF conversion.
  for (let i = 0; i < max; i++) {
    const ja = jsf[0][i];
    const jb = jsf[1][i];

    naf[i] = jsfIndex[(ja + 1) * 3 + (jb + 1)];
  }

  return naf;
}

/*
 * Helpers
 */

function assert(val, msg) {
  if (!val) {
    const err = new Error(msg || 'Assertion failed');

    if (Error.captureStackTrace)
      Error.captureStackTrace(err, assert);

    throw err;
  }
}

function wrapErrors(fn) {
  assert(typeof fn === 'function');

  try {
    return fn();
  } catch (e) {
    if (e.message === 'X is not a square mod P.'
        || e.message === 'Not invertible.') {
      throw new Error('Invalid point.');
    }
    throw e;
  }
}

function mod(x, y) {
  // Euclidean modulo.
  let r = x % y;

  if (r < 0) {
    if (y < 0)
      r -= y;
    else
      r += y;
  }

  return r;
}

function cubeRoot(x) {
  assert(x instanceof BN);
  assert(x.red);

  const p = x.red.m;

  if (p.cmpn(3) <= 0)
    return x.clone();

  // p = 2 mod 3
  if (p.modrn(3) === 2) {
    // e = (2 * p - 1) / 3
    const e = p.ushln(1).isubn(1).idivn(3);
    return x.redPow(e);
  }

  const mod9 = p.modrn(9);

  // p = 4 mod 9
  if (mod9 === 4) {
    // e = (2 * p + 1) / 9
    const e = p.ushln(1).iaddn(1).idivn(9);
    const r = x.redPow(e);
    const c = r.redSqr().redMul(r);

    if (!c.eq(x))
      throw new Error('X is not a cube mod P.');

    return r;
  }

  // p = 7 mod 9
  if (mod9 === 7) {
    // e = (p + 2) / 9
    const e = p.addn(2).idivn(9);
    const r = x.redPow(e);
    const c = r.redSqr().redMul(r);

    if (!c.eq(x))
      throw new Error('X is not a cube mod P.');

    return r;
  }

  throw new Error('Not implemented.');
}

function cubeRoots(x) {
  const r0 = cubeRoot(x);

  // p = 1 mod 3
  if (x.red.m.modrn(3) === 1) {
    // Multiply by roots of unity to find other roots.
    const two = new BN(2).toRed(x.red);
    const three = new BN(3).toRed(x.red);
    const i2 = two.redInvert();
    const s1 = three.redNeg().redSqrt().redMul(i2);
    const s2 = s1.redNeg();
    const u1 = s1.redSub(i2);
    const u2 = s2.redSub(i2);
    const r1 = r0.redMul(u1);
    const r2 = r0.redMul(u2);

    return [r0, r1, r2];
  }

  // p = 2 mod 3 guarantees 1 cube root per element.
  return [r0];
}

function uncube(x) {
  // Find a cube root which is also a quadratic residue.
  for (const root of cubeRoots(x)) {
    if (root.redJacobi() >= 0)
      return root;
  }

  throw new Error('X^(1/3) is not a square mod P.');
}

function randomInt(rng) {
  return BN.randomBits(rng, 32).toNumber();
}

function memoize(method, self) {
  const cache = new WeakMap();

  return function memoized(curve, invert) {
    const i = invert & 1;
    const item = cache.get(curve);

    if (item && item[i] !== null)
      return item[i];

    const result = method.call(self, curve, invert);

    if (!cache.has(curve))
      cache.set(curve, [null, null]);

    cache.get(curve)[i] = result;

    return result;
  };
}

function toPretty(x, size) {
  assert(x instanceof BN);
  assert((size >>> 0) === size);

  if (size & 7)
    size += 8 - (size & 7);

  const str = x.toString(16, size);
  const chunks = [];
  const out = [];

  assert((str.length & 7) === 0);

  for (let i = 0; i < str.length; i += 8)
    chunks.push(str.slice(i, i + 8));

  for (let i = 0; i < chunks.length; i += 4)
    out.push(chunks.slice(i, i + 4).join(' '));

  return out;
}

/*
 * Expose
 */

exports.Curve = Curve;
exports.Point = Point;
exports.ShortCurve = ShortCurve;
exports.ShortPoint = ShortPoint;
exports.JPoint = JPoint;
exports.MontCurve = MontCurve;
exports.MontPoint = MontPoint;
exports.XPoint = XPoint;
exports.EdwardsCurve = EdwardsCurve;
exports.EdwardsPoint = EdwardsPoint;
exports.curves = curves;
exports.curve = curve;
exports.register = register;
}],
[/* 43 */ 'bcrypto', '/lib/js/precomputed/secp256k1.json', function(exports, module, __filename, __dirname, __meta) {
module.exports = {
  "naf": {
    "width": 9,
    "points": [
      [
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"
      ],
      [
        "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        "d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6"
      ],
      [
        "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
        "6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da"
      ],
      [
        "acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
        "cc338921b0a7d9fd64380971763b61e9add888a4375f8e0f05cc262ac64f9c37"
      ],
      [
        "774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
        "d984a032eb6b5e190243dd56d7b7b365372db1e2dff9d6a8301d74c9c953c61b"
      ],
      [
        "f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
        "0ab0902e8d880a89758212eb65cdaf473a1a06da521fa91f29b5cb52db03ed81"
      ],
      [
        "d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
        "581e2872a86c72a683842ec228cc6defea40af2bd896d3a5c504dc9ff6a26b58"
      ],
      [
        "defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
        "4211ab0694635168e997b0ead2a93daeced1f4a04a95c0f6cfb199f69e56eb77"
      ],
      [
        "2b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c",
        "85e89bc037945d93b343083b5a1c86131a01f60c50269763b570c854e5c09b7a"
      ],
      [
        "352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5",
        "321eb4075348f534d59c18259dda3e1f4a1b3b2e71b1039c67bd3d8bcf81998c"
      ],
      [
        "2fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f",
        "02de1068295dd865b64569335bd5dd80181d70ecfc882648423ba76b532b7d67"
      ],
      [
        "9248279b09b4d68dab21a9b066edda83263c3d84e09572e269ca0cd7f5453714",
        "73016f7bf234aade5d1aa71bdea2b1ff3fc0de2a887912ffe54a32ce97cb3402"
      ],
      [
        "daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729",
        "a69dce4a7d6c98e8d4a1aca87ef8d7003f83c230f3afa726ab40e52290be1c55"
      ],
      [
        "c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db",
        "2119a460ce326cdc76c45926c982fdac0e106e861edf61c5a039063f0e0e6482"
      ],
      [
        "6a245bf6dc698504c89a20cfded60853152b695336c28063b61c65cbd269e6b4",
        "e022cf42c2bd4a708b3f5126f16a24ad8b33ba48d0423b6efd5e6348100d8a82"
      ],
      [
        "1697ffa6fd9de627c077e3d2fe541084ce13300b0bec1146f95ae57f0d0bd6a5",
        "b9c398f186806f5d27561506e4557433a2cf15009e498ae7adee9d63d01b2396"
      ],
      [
        "605bdb019981718b986d0f07e834cb0d9deb8360ffb7f61df982345ef27a7479",
        "02972d2de4f8d20681a78d93ec96fe23c26bfae84fb14db43b01e1e9056b8c49"
      ],
      [
        "62d14dab4150bf497402fdc45a215e10dcb01c354959b10cfe31c7e9d87ff33d",
        "80fc06bd8cc5b01098088a1950eed0db01aa132967ab472235f5642483b25eaf"
      ],
      [
        "80c60ad0040f27dade5b4b06c408e56b2c50e9f56b9b8b425e555c2f86308b6f",
        "1c38303f1cc5c30f26e66bad7fe72f70a65eed4cbe7024eb1aa01f56430bd57a"
      ],
      [
        "7a9375ad6167ad54aa74c6348cc54d344cc5dc9487d847049d5eabb0fa03c8fb",
        "0d0e3fa9eca8726909559e0d79269046bdc59ea10c70ce2b02d499ec224dc7f7"
      ],
      [
        "d528ecd9b696b54c907a9ed045447a79bb408ec39b68df504bb51f459bc3ffc9",
        "eecf41253136e5f99966f21881fd656ebc4345405c520dbc063465b521409933"
      ],
      [
        "049370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963",
        "758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a"
      ],
      [
        "77f230936ee88cbbd73df930d64702ef881d811e0e1498e2f1c13eb1fc345d74",
        "958ef42a7886b6400a08266e9ba1b37896c95330d97077cbbe8eb3c7671c60d6"
      ],
      [
        "f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530",
        "e0dedc9b3b2f8dad4da1f32dec2531df9eb5fbeb0598e4fd1a117dba703a3c37"
      ],
      [
        "463b3d9f662621fb1b4be8fbbe2520125a216cdfc9dae3debcba4850c690d45b",
        "5ed430d78c296c3543114306dd8622d7c622e27c970a1de31cb377b01af7307e"
      ],
      [
        "f16f804244e46e2a09232d4aff3b59976b98fac14328a2d1a32496b49998f247",
        "cedabd9b82203f7e13d206fcdf4e33d92a6c53c26e5cce26d6579962c4e31df6"
      ],
      [
        "caf754272dc84563b0352b7a14311af55d245315ace27c65369e15f7151d41d1",
        "cb474660ef35f5f2a41b643fa5e460575f4fa9b7962232a5c32f908318a04476"
      ],
      [
        "2600ca4b282cb986f85d0f1709979d8b44a09c07cb86d7c124497bc86f082120",
        "4119b88753c15bd6a693b03fcddbb45d5ac6be74ab5f0ef44b0be9475a7e4b40"
      ],
      [
        "7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435",
        "091b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61"
      ],
      [
        "754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18",
        "0673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683"
      ],
      [
        "e3e6bd1071a1e96aff57859c82d570f0330800661d1c952f9fe2694691d9b9e8",
        "59c9e0bba394e76f40c0aa58379a3cb6a5a2283993e90c4167002af4920e37f5"
      ],
      [
        "186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb",
        "3b952d32c67cf77e2e17446e204180ab21fb8090895138b4a4a797f86e80888b"
      ],
      [
        "df9d70a6b9876ce544c98561f4be4f725442e6d2b737d9c91a8321724ce0963f",
        "55eb2dafd84d6ccd5f862b785dc39d4ab157222720ef9da217b8c45cf2ba2417"
      ],
      [
        "5edd5cc23c51e87a497ca815d5dce0f8ab52554f849ed8995de64c5f34ce7143",
        "efae9c8dbc14130661e8cec030c89ad0c13c66c0d17a2905cdc706ab7399a868"
      ],
      [
        "290798c2b6476830da12fe02287e9e777aa3fba1c355b17a722d362f84614fba",
        "e38da76dcd440621988d00bcf79af25d5b29c094db2a23146d003afd41943e7a"
      ],
      [
        "af3c423a95d9f5b3054754efa150ac39cd29552fe360257362dfdecef4053b45",
        "f98a3fd831eb2b749a93b0e6f35cfb40c8cd5aa667a15581bc2feded498fd9c6"
      ],
      [
        "766dbb24d134e745cccaa28c99bf274906bb66b26dcf98df8d2fed50d884249a",
        "744b1152eacbe5e38dcc887980da38b897584a65fa06cedd2c924f97cbac5996"
      ],
      [
        "59dbf46f8c94759ba21277c33784f41645f7b44f6c596a58ce92e666191abe3e",
        "c534ad44175fbc300f4ea6ce648309a042ce739a7919798cd85e216c4a307f6e"
      ],
      [
        "f13ada95103c4537305e691e74e9a4a8dd647e711a95e73cb62dc6018cfd87b8",
        "e13817b44ee14de663bf4bc808341f326949e21a6a75c2570778419bdaf5733d"
      ],
      [
        "7754b4fa0e8aced06d4167a2c59cca4cda1869c06ebadfb6488550015a88522c",
        "30e93e864e669d82224b967c3020b8fa8d1e4e350b6cbcc537a48b57841163a2"
      ],
      [
        "948dcadf5990e048aa3874d46abef9d701858f95de8041d2a6828c99e2262519",
        "e491a42537f6e597d5d28a3224b1bc25df9154efbd2ef1d2cbba2cae5347d57e"
      ],
      [
        "7962414450c76c1689c7b48f8202ec37fb224cf5ac0bfa1570328a8a3d7c77ab",
        "100b610ec4ffb4760d5c1fc133ef6f6b12507a051f04ac5760afa5b29db83437"
      ],
      [
        "3514087834964b54b15b160644d915485a16977225b8847bb0dd085137ec47ca",
        "ef0afbb2056205448e1652c48e8127fc6039e77c15c2378b7e7d15a0de293311"
      ],
      [
        "d3cc30ad6b483e4bc79ce2c9dd8bc54993e947eb8df787b442943d3f7b527eaf",
        "8b378a22d827278d89c5e9be8f9508ae3c2ad46290358630afb34db04eede0a4"
      ],
      [
        "1624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff4847610",
        "68651cf9b6da903e0914448c6cd9d4ca896878f5282be4c8cc06e2a404078575"
      ],
      [
        "733ce80da955a8a26902c95633e62a985192474b5af207da6df7b4fd5fc61cd4",
        "f5435a2bd2badf7d485a4d8b8db9fcce3e1ef8e0201e4578c54673bc1dc5ea1d"
      ],
      [
        "15d9441254945064cf1a1c33bbd3b49f8966c5092171e699ef258dfab81c045c",
        "d56eb30b69463e7234f5137b73b84177434800bacebfc685fc37bbe9efe4070d"
      ],
      [
        "a1d0fcf2ec9de675b612136e5ce70d271c21417c9d2b8aaaac138599d0717940",
        "edd77f50bcb5a3cab2e90737309667f2641462a54070f3d519212d39c197a629"
      ],
      [
        "e22fbe15c0af8ccc5780c0735f84dbe9a790badee8245c06c7ca37331cb36980",
        "0a855babad5cd60c88b430a69f53a1a7a38289154964799be43d06d77d31da06"
      ],
      [
        "311091dd9860e8e20ee13473c1155f5f69635e394704eaa74009452246cfa9b3",
        "66db656f87d1f04fffd1f04788c06830871ec5a64feee685bd80f0b1286d8374"
      ],
      [
        "34c1fd04d301be89b31c0442d3e6ac24883928b45a9340781867d4232ec2dbdf",
        "09414685e97b1b5954bd46f730174136d57f1ceeb487443dc5321857ba73abee"
      ],
      [
        "f219ea5d6b54701c1c14de5b557eb42a8d13f3abbcd08affcc2a5e6b049b8d63",
        "4cb95957e83d40b0f73af4544cccf6b1f4b08d3c07b27fb8d8c2962a400766d1"
      ],
      [
        "d7b8740f74a8fbaab1f683db8f45de26543a5490bca627087236912469a0b448",
        "fa77968128d9c92ee1010f337ad4717eff15db5ed3c049b3411e0315eaa4593b"
      ],
      [
        "32d31c222f8f6f0ef86f7c98d3a3335ead5bcd32abdd94289fe4d3091aa824bf",
        "5f3032f5892156e39ccd3d7915b9e1da2e6dac9e6f26e961118d14b8462e1661"
      ],
      [
        "7461f371914ab32671045a155d9831ea8793d77cd59592c4340f86cbc18347b5",
        "8ec0ba238b96bec0cbdddcae0aa442542eee1ff50c986ea6b39847b3cc092ff6"
      ],
      [
        "ee079adb1df1860074356a25aa38206a6d716b2c3e67453d287698bad7b2b2d6",
        "8dc2412aafe3be5c4c5f37e0ecc5f9f6a446989af04c4e25ebaac479ec1c8c1e"
      ],
      [
        "16ec93e447ec83f0467b18302ee620f7e65de331874c9dc72bfd8616ba9da6b5",
        "5e4631150e62fb40d0e8c2a7ca5804a39d58186a50e497139626778e25b0674d"
      ],
      [
        "eaa5f980c245f6f038978290afa70b6bd8855897f98b6aa485b96065d537bd99",
        "f65f5d3e292c2e0819a528391c994624d784869d7e6ea67fb18041024edc07dc"
      ],
      [
        "078c9407544ac132692ee1910a02439958ae04877151342ea96c4b6b35a49f51",
        "f3e0319169eb9b85d5404795539a5e68fa1fbd583c064d2462b675f194a3ddb4"
      ],
      [
        "494f4be219a1a77016dcd838431aea0001cdc8ae7a6fc688726578d9702857a5",
        "42242a969283a5f339ba7f075e36ba2af925ce30d767ed6e55f4b031880d562c"
      ],
      [
        "a598a8030da6d86c6bc7f2f5144ea549d28211ea58faa70ebf4c1e665c1fe9b5",
        "204b5d6f84822c307e4b4a7140737aec23fc63b65b35f86a10026dbd2d864e6b"
      ],
      [
        "c41916365abb2b5d09192f5f2dbeafec208f020f12570a184dbadc3e58595997",
        "04f14351d0087efa49d245b328984989d5caf9450f34bfc0ed16e96b58fa9913"
      ],
      [
        "841d6063a586fa475a724604da03bc5b92a2e0d2e0a36acfe4c73a5514742881",
        "073867f59c0659e81904f9a1c7543698e62562d6744c169ce7a36de01a8d6154"
      ],
      [
        "5e95bb399a6971d376026947f89bde2f282b33810928be4ded112ac4d70e20d5",
        "39f23f366809085beebfc71181313775a99c9aed7d8ba38b161384c746012865"
      ],
      [
        "36e4641a53948fd476c39f8a99fd974e5ec07564b5315d8bf99471bca0ef2f66",
        "d2424b1b1abe4eb8164227b085c9aa9456ea13493fd563e06fd51cf5694c78fc"
      ],
      [
        "0336581ea7bfbbb290c191a2f507a41cf5643842170e914faeab27c2c579f726",
        "ead12168595fe1be99252129b6e56b3391f7ab1410cd1e0ef3dcdcabd2fda224"
      ],
      [
        "8ab89816dadfd6b6a1f2634fcf00ec8403781025ed6890c4849742706bd43ede",
        "6fdcef09f2f6d0a044e654aef624136f503d459c3e89845858a47a9129cdd24e"
      ],
      [
        "1e33f1a746c9c5778133344d9299fcaa20b0938e8acff2544bb40284b8c5fb94",
        "060660257dd11b3aa9c8ed618d24edff2306d320f1d03010e33a7d2057f3b3b6"
      ],
      [
        "85b7c1dcb3cec1b7ee7f30ded79dd20a0ed1f4cc18cbcfcfa410361fd8f08f31",
        "3d98a9cdd026dd43f39048f25a8847f4fcafad1895d7a633c6fed3c35e999511"
      ],
      [
        "29df9fbd8d9e46509275f4b125d6d45d7fbe9a3b878a7af872a2800661ac5f51",
        "0b4c4fe99c775a606e2d8862179139ffda61dc861c019e55cd2876eb2a27d84b"
      ],
      [
        "a0b1cae06b0a847a3fea6e671aaf8adfdfe58ca2f768105c8082b2e449fce252",
        "ae434102edde0958ec4b19d917a6a28e6b72da1834aff0e650f049503a296cf2"
      ],
      [
        "04e8ceafb9b3e9a136dc7ff67e840295b499dfb3b2133e4ba113f2e4c0e121e5",
        "cf2174118c8b6d7a4b48f6d534ce5c79422c086a63460502b827ce62a326683c"
      ],
      [
        "d24a44e047e19b6f5afb81c7ca2f69080a5076689a010919f42725c2b789a33b",
        "6fb8d5591b466f8fc63db50f1c0f1c69013f996887b8244d2cdec417afea8fa3"
      ],
      [
        "ea01606a7a6c9cdd249fdfcfacb99584001edd28abbab77b5104e98e8e3b35d4",
        "322af4908c7312b0cfbfe369f7a7b3cdb7d4494bc2823700cfd652188a3ea98d"
      ],
      [
        "af8addbf2b661c8a6c6328655eb96651252007d8c5ea31be4ad196de8ce2131f",
        "6749e67c029b85f52a034eafd096836b2520818680e26ac8f3dfbcdb71749700"
      ],
      [
        "e3ae1974566ca06cc516d47e0fb165a674a3dabcfca15e722f0e3450f45889",
        "2aeabe7e4531510116217f07bf4d07300de97e4874f81f533420a72eeb0bd6a4"
      ],
      [
        "591ee355313d99721cf6993ffed1e3e301993ff3ed258802075ea8ced397e246",
        "b0ea558a113c30bea60fc4775460c7901ff0b053d25ca2bdeee98f1a4be5d196"
      ],
      [
        "11396d55fda54c49f19aa97318d8da61fa8584e47b084945077cf03255b52984",
        "998c74a8cd45ac01289d5833a7beb4744ff536b01b257be4c5767bea93ea57a4"
      ],
      [
        "3c5d2a1ba39c5a1790000738c9e0c40b8dcdfd5468754b6405540157e017aa7a",
        "b2284279995a34e2f9d4de7396fc18b80f9b8b9fdd270f6661f79ca4c81bd257"
      ],
      [
        "cc8704b8a60a0defa3a99a7299f2e9c3fbc395afb04ac078425ef8a1793cc030",
        "bdd46039feed17881d1e0862db347f8cf395b74fc4bcdc4e940b74e3ac1f1b13"
      ],
      [
        "c533e4f7ea8555aacd9777ac5cad29b97dd4defccc53ee7ea204119b2889b197",
        "6f0a256bc5efdf429a2fb6242f1a43a2d9b925bb4a4b3a26bb8e0f45eb596096"
      ],
      [
        "0c14f8f2ccb27d6f109f6d08d03cc96a69ba8c34eec07bbcf566d48e33da6593",
        "c359d6923bb398f7fd4473e16fe1c28475b740dd098075e6c0e8649113dc3a38"
      ],
      [
        "a6cbc3046bc6a450bac24789fa17115a4c9739ed75f8f21ce441f72e0b90e6ef",
        "021ae7f4680e889bb130619e2c0f95a360ceb573c70603139862afd617fa9b9f"
      ],
      [
        "347d6d9a02c48927ebfb86c1359b1caf130a3c0267d11ce6344b39f99d43cc38",
        "60ea7f61a353524d1c987f6ecec92f086d565ab687870cb12689ff1e31c74448"
      ],
      [
        "da6545d2181db8d983f7dcb375ef5866d47c67b1bf31c8cf855ef7437b72656a",
        "49b96715ab6878a79e78f07ce5680c5d6673051b4935bd897fea824b77dc208a"
      ],
      [
        "c40747cc9d012cb1a13b8148309c6de7ec25d6945d657146b9d5994b8feb1111",
        "5ca560753be2a12fc6de6caf2cb489565db936156b9514e1bb5e83037e0fa2d4"
      ],
      [
        "4e42c8ec82c99798ccf3a610be870e78338c7f713348bd34c8203ef4037f3502",
        "7571d74ee5e0fb92a7a8b33a07783341a5492144cc54bcc40a94473693606437"
      ],
      [
        "3775ab7089bc6af823aba2e1af70b236d251cadb0c86743287522a1b3b0dedea",
        "be52d107bcfa09d8bcb9736a828cfa7fac8db17bf7a76a2c42ad961409018cf7"
      ],
      [
        "cee31cbf7e34ec379d94fb814d3d775ad954595d1314ba8846959e3e82f74e26",
        "8fd64a14c06b589c26b947ae2bcf6bfa0149ef0be14ed4d80f448a01c43b1c6d"
      ],
      [
        "b4f9eaea09b6917619f6ea6a4eb5464efddb58fd45b1ebefcdc1a01d08b47986",
        "39e5c9925b5a54b07433a4f18c61726f8bb131c012ca542eb24a8ac07200682a"
      ],
      [
        "d4263dfc3d2df923a0179a48966d30ce84e2515afc3dccc1b77907792ebcc60e",
        "62dfaf07a0f78feb30e30d6295853ce189e127760ad6cf7fae164e122a208d54"
      ],
      [
        "48457524820fa65a4f8d35eb6930857c0032acc0a4a2de422233eeda897612c4",
        "25a748ab367979d98733c38a1fa1c2e7dc6cc07db2d60a9ae7a76aaa49bd0f77"
      ],
      [
        "dfeeef1881101f2cb11644f3a2afdfc2045e19919152923f367a1767c11cceda",
        "ecfb7056cf1de042f9420bab396793c0c390bde74b4bbdff16a83ae09a9a7517"
      ],
      [
        "6d7ef6b17543f8373c573f44e1f389835d89bcbc6062ced36c82df83b8fae859",
        "cd450ec335438986dfefa10c57fea9bcc521a0959b2d80bbf74b190dca712d10"
      ],
      [
        "e75605d59102a5a2684500d3b991f2e3f3c88b93225547035af25af66e04541f",
        "f5c54754a8f71ee540b9b48728473e314f729ac5308b06938360990e2bfad125"
      ],
      [
        "eb98660f4c4dfaa06a2be453d5020bc99a0c2e60abe388457dd43fefb1ed620c",
        "6cb9a8876d9cb8520609af3add26cd20a0a7cd8a9411131ce85f44100099223e"
      ],
      [
        "13e87b027d8514d35939f2e6892b19922154596941888336dc3563e3b8dba942",
        "fef5a3c68059a6dec5d624114bf1e91aac2b9da568d6abeb2570d55646b8adf1"
      ],
      [
        "ee163026e9fd6fe017c38f06a5be6fc125424b371ce2708e7bf4491691e5764a",
        "1acb250f255dd61c43d94ccc670d0f58f49ae3fa15b96623e5430da0ad6c62b2"
      ],
      [
        "b268f5ef9ad51e4d78de3a750c2dc89b1e626d43505867999932e5db33af3d80",
        "5f310d4b3c99b9ebb19f77d41c1dee018cf0d34fd4191614003e945a1216e423"
      ],
      [
        "ff07f3118a9df035e9fad85eb6c7bfe42b02f01ca99ceea3bf7ffdba93c4750d",
        "438136d603e858a3a5c440c38eccbaddc1d2942114e2eddd4740d098ced1f0d8"
      ],
      [
        "8d8b9855c7c052a34146fd20ffb658bea4b9f69e0d825ebec16e8c3ce2b526a1",
        "cdb559eedc2d79f926baf44fb84ea4d44bcf50fee51d7ceb30e2e7f463036758"
      ],
      [
        "52db0b5384dfbf05bfa9d472d7ae26dfe4b851ceca91b1eba54263180da32b63",
        "0c3b997d050ee5d423ebaf66a6db9f57b3180c902875679de924b69d84a7b375"
      ],
      [
        "e62f9490d3d51da6395efd24e80919cc7d0f29c3f3fa48c6fff543becbd43352",
        "6d89ad7ba4876b0b22c2ca280c682862f342c8591f1daf5170e07bfd9ccafa7d"
      ],
      [
        "7f30ea2476b399b4957509c88f77d0191afa2ff5cb7b14fd6d8e7d65aaab1193",
        "ca5ef7d4b231c94c3b15389a5f6311e9daff7bb67b103e9880ef4bff637acaec"
      ],
      [
        "5098ff1e1d9f14fb46a210fada6c903fef0fb7b4a1dd1d9ac60a0361800b7a00",
        "09731141d81fc8f8084d37c6e7542006b3ee1b40d60dfe5362a5b132fd17ddc0"
      ],
      [
        "32b78c7de9ee512a72895be6b9cbefa6e2f3c4ccce445c96b9f2c81e2778ad58",
        "ee1849f513df71e32efc3896ee28260c73bb80547ae2275ba497237794c8753c"
      ],
      [
        "e2cb74fddc8e9fbcd076eef2a7c72b0ce37d50f08269dfc074b581550547a4f7",
        "d3aa2ed71c9dd2247a62df062736eb0baddea9e36122d2be8641abcb005cc4a4"
      ],
      [
        "8438447566d4d7bedadc299496ab357426009a35f235cb141be0d99cd10ae3a8",
        "c4e1020916980a4da5d01ac5e6ad330734ef0d7906631c4f2390426b2edd791f"
      ],
      [
        "4162d488b89402039b584c6fc6c308870587d9c46f660b878ab65c82c711d67e",
        "67163e903236289f776f22c25fb8a3afc1732f2b84b4e95dbda47ae5a0852649"
      ],
      [
        "3fad3fa84caf0f34f0f89bfd2dcf54fc175d767aec3e50684f3ba4a4bf5f683d",
        "0cd1bc7cb6cc407bb2f0ca647c718a730cf71872e7d0d2a53fa20efcdfe61826"
      ],
      [
        "674f2600a3007a00568c1a7ce05d0816c1fb84bf1370798f1c69532faeb1a86b",
        "299d21f9413f33b3edf43b257004580b70db57da0b182259e09eecc69e0d38a5"
      ],
      [
        "d32f4da54ade74abb81b815ad1fb3b263d82d6c692714bcff87d29bd5ee9f08f",
        "f9429e738b8e53b968e99016c059707782e14f4535359d582fc416910b3eea87"
      ],
      [
        "30e4e670435385556e593657135845d36fbb6931f72b08cb1ed954f1e3ce3ff6",
        "462f9bce619898638499350113bbc9b10a878d35da70740dc695a559eb88db7b"
      ],
      [
        "be2062003c51cc3004682904330e4dee7f3dcd10b01e580bf1971b04d4cad297",
        "62188bc49d61e5428573d48a74e1c655b1c61090905682a0d5558ed72dccb9bc"
      ],
      [
        "93144423ace3451ed29e0fb9ac2af211cb6e84a601df5993c419859fff5df04a",
        "7c10dfb164c3425f5c71a3f9d7992038f1065224f72bb9d1d902a6d13037b47c"
      ],
      [
        "b015f8044f5fcbdcf21ca26d6c34fb8197829205c7b7d2a7cb66418c157b112c",
        "ab8c1e086d04e813744a655b2df8d5f83b3cdc6faa3088c1d3aea1454e3a1d5f"
      ],
      [
        "d5e9e1da649d97d89e4868117a465a3a4f8a18de57a140d36b3f2af341a21b52",
        "4cb04437f391ed73111a13cc1d4dd0db1693465c2240480d8955e8592f27447a"
      ],
      [
        "d3ae41047dd7ca065dbf8ed77b992439983005cd72e16d6f996a5316d36966bb",
        "bd1aeb21ad22ebb22a10f0303417c6d964f8cdd7df0aca614b10dc14d125ac46"
      ],
      [
        "463e2763d885f958fc66cdd22800f0a487197d0a82e377b49f80af87c897b065",
        "bfefacdb0e5d0fd7df3a311a94de062b26b80c61fbc97508b79992671ef7ca7f"
      ],
      [
        "7985fdfd127c0567c6f53ec1bb63ec3158e597c40bfe747c83cddfc910641917",
        "603c12daf3d9862ef2b25fe1de289aed24ed291e0ec6708703a5bd567f32ed03"
      ],
      [
        "74a1ad6b5f76e39db2dd249410eac7f99e74c59cb83d2d0ed5ff1543da7703e9",
        "cc6157ef18c9c63cd6193d83631bbea0093e0968942e8c33d5737fd790e0db08"
      ],
      [
        "30682a50703375f602d416664ba19b7fc9bab42c72747463a71d0896b22f6da3",
        "553e04f6b018b4fa6c8f39e7f311d3176290d0e0f19ca73f17714d9977a22ff8"
      ],
      [
        "9e2158f0d7c0d5f26c3791efefa79597654e7a2b2464f52b1ee6c1347769ef57",
        "0712fcdd1b9053f09003a3481fa7762e9ffd7c8ef35a38509e2fbf2629008373"
      ],
      [
        "176e26989a43c9cfeba4029c202538c28172e566e3c4fce7322857f3be327d66",
        "ed8cc9d04b29eb877d270b4878dc43c19aefd31f4eee09ee7b47834c1fa4b1c3"
      ],
      [
        "75d46efea3771e6e68abb89a13ad747ecf1892393dfc4f1b7004788c50374da8",
        "9852390a99507679fd0b86fd2b39a868d7efc22151346e1a3ca4726586a6bed8"
      ],
      [
        "809a20c67d64900ffb698c4c825f6d5f2310fb0451c869345b7319f645605721",
        "9e994980d9917e22b76b061927fa04143d096ccc54963e6a5ebfa5f3f8e286c1"
      ],
      [
        "1b38903a43f7f114ed4500b4eac7083fdefece1cf29c63528d563446f972c180",
        "4036edc931a60ae889353f77fd53de4a2708b26b6f5da72ad3394119daf408f9"
      ]
    ]
  },
  "doubles": {
    "step": 4,
    "points": [
      [
        "e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a",
        "f7e3507399e595929db99f34f57937101296891e44d23f0be1f32cce69616821"
      ],
      [
        "8282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508",
        "11f8a8098557dfe45e8256e830b60ace62d613ac2f7b17bed31b6eaff6e26caf"
      ],
      [
        "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739",
        "d3506e0d9e3c79eba4ef97a51ff71f5eacb5955add24345c6efa6ffee9fed695"
      ],
      [
        "363d90d447b00c9c99ceac05b6262ee053441c7e55552ffe526bad8f83ff4640",
        "04e273adfc732221953b445397f3363145b9a89008199ecb62003c7f3bee9de9"
      ],
      [
        "8b4b5f165df3c2be8c6244b5b745638843e4a781a15bcd1b69f79a55dffdf80c",
        "4aad0a6f68d308b4b3fbd7813ab0da04f9e336546162ee56b3eff0c65fd4fd36"
      ],
      [
        "723cbaa6e5db996d6bf771c00bd548c7b700dbffa6c0e77bcb6115925232fcda",
        "96e867b5595cc498a921137488824d6e2660a0653779494801dc069d9eb39f5f"
      ],
      [
        "eebfa4d493bebf98ba5feec812c2d3b50947961237a919839a533eca0e7dd7fa",
        "5d9a8ca3970ef0f269ee7edaf178089d9ae4cdc3a711f712ddfd4fdae1de8999"
      ],
      [
        "100f44da696e71672791d0a09b7bde459f1215a29b3c03bfefd7835b39a48db0",
        "cdd9e13192a00b772ec8f3300c090666b7ff4a18ff5195ac0fbd5cd62bc65a09"
      ],
      [
        "e1031be262c7ed1b1dc9227a4a04c017a77f8d4464f3b3852c8acde6e534fd2d",
        "9d7061928940405e6bb6a4176597535af292dd419e1ced79a44f18f29456a00d"
      ],
      [
        "feea6cae46d55b530ac2839f143bd7ec5cf8b266a41d6af52d5e688d9094696d",
        "e57c6b6c97dce1bab06e4e12bf3ecd5c981c8957cc41442d3155debf18090088"
      ],
      [
        "da67a91d91049cdcb367be4be6ffca3cfeed657d808583de33fa978bc1ec6cb1",
        "9bacaa35481642bc41f463f7ec9780e5dec7adc508f740a17e9ea8e27a68be1d"
      ],
      [
        "53904faa0b334cdda6e000935ef22151ec08d0f7bb11069f57545ccc1a37b7c0",
        "5bc087d0bc80106d88c9eccac20d3c1c13999981e14434699dcb096b022771c8"
      ],
      [
        "8e7bcd0bd35983a7719cca7764ca906779b53a043a9b8bcaeff959f43ad86047",
        "10b7770b2a3da4b3940310420ca9514579e88e2e47fd68b3ea10047e8460372a"
      ],
      [
        "385eed34c1cdff21e6d0818689b81bde71a7f4f18397e6690a841e1599c43862",
        "283bebc3e8ea23f56701de19e9ebf4576b304eec2086dc8cc0458fe5542e5453"
      ],
      [
        "06f9d9b803ecf191637c73a4413dfa180fddf84a5947fbc9c606ed86c3fac3a7",
        "7c80c68e603059ba69b8e2a30e45c4d47ea4dd2f5c281002d86890603a842160"
      ],
      [
        "3322d401243c4e2582a2147c104d6ecbf774d163db0f5e5313b7e0e742d0e6bd",
        "56e70797e9664ef5bfb019bc4ddaf9b72805f63ea2873af624f3a2e96c28b2a0"
      ],
      [
        "85672c7d2de0b7da2bd1770d89665868741b3f9af7643397721d74d28134ab83",
        "7c481b9b5b43b2eb6374049bfa62c2e5e77f17fcc5298f44c8e3094f790313a6"
      ],
      [
        "0948bf809b1988a46b06c9f1919413b10f9226c60f668832ffd959af60c82a0a",
        "53a562856dcb6646dc6b74c5d1c3418c6d4dff08c97cd2bed4cb7f88d8c8e589"
      ],
      [
        "6260ce7f461801c34f067ce0f02873a8f1b0e44dfc69752accecd819f38fd8e8",
        "bc2da82b6fa5b571a7f09049776a1ef7ecd292238051c198c1a84e95b2b4ae17"
      ],
      [
        "e5037de0afc1d8d43d8348414bbf4103043ec8f575bfdc432953cc8d2037fa2d",
        "4571534baa94d3b5f9f98d09fb990bddbd5f5b03ec481f10e0e5dc841d755bda"
      ],
      [
        "e06372b0f4a207adf5ea905e8f1771b4e7e8dbd1c6a6c5b725866a0ae4fce725",
        "7a908974bce18cfe12a27bb2ad5a488cd7484a7787104870b27034f94eee31dd"
      ],
      [
        "213c7a715cd5d45358d0bbf9dc0ce02204b10bdde2a3f58540ad6908d0559754",
        "4b6dad0b5ae462507013ad06245ba190bb4850f5f36a7eeddff2c27534b458f2"
      ],
      [
        "4e7c272a7af4b34e8dbb9352a5419a87e2838c70adc62cddf0cc3a3b08fbd53c",
        "17749c766c9d0b18e16fd09f6def681b530b9614bff7dd33e0b3941817dcaae6"
      ],
      [
        "fea74e3dbe778b1b10f238ad61686aa5c76e3db2be43057632427e2840fb27b6",
        "6e0568db9b0b13297cf674deccb6af93126b596b973f7b77701d3db7f23cb96f"
      ],
      [
        "76e64113f677cf0e10a2570d599968d31544e179b760432952c02a4417bdde39",
        "c90ddf8dee4e95cf577066d70681f0d35e2a33d2b56d2032b4b1752d1901ac01"
      ],
      [
        "c738c56b03b2abe1e8281baa743f8f9a8f7cc643df26cbee3ab150242bcbb891",
        "893fb578951ad2537f718f2eacbfbbbb82314eef7880cfe917e735d9699a84c3"
      ],
      [
        "d895626548b65b81e264c7637c972877d1d72e5f3a925014372e9f6588f6c14b",
        "febfaa38f2bc7eae728ec60818c340eb03428d632bb067e179363ed75d7d991f"
      ],
      [
        "b8da94032a957518eb0f6433571e8761ceffc73693e84edd49150a564f676e03",
        "2804dfa44805a1e4d7c99cc9762808b092cc584d95ff3b511488e4e74efdf6e7"
      ],
      [
        "e80fea14441fb33a7d8adab9475d7fab2019effb5156a792f1a11778e3c0df5d",
        "eed1de7f638e00771e89768ca3ca94472d155e80af322ea9fcb4291b6ac9ec78"
      ],
      [
        "a301697bdfcd704313ba48e51d567543f2a182031efd6915ddc07bbcc4e16070",
        "7370f91cfb67e4f5081809fa25d40f9b1735dbf7c0a11a130c0d1a041e177ea1"
      ],
      [
        "90ad85b389d6b936463f9d0512678de208cc330b11307fffab7ac63e3fb04ed4",
        "0e507a3620a38261affdcbd9427222b839aefabe1582894d991d4d48cb6ef150"
      ],
      [
        "8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da",
        "662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82"
      ],
      [
        "e4f3fb0176af85d65ff99ff9198c36091f48e86503681e3e6686fd5053231e11",
        "1e63633ad0ef4f1c1661a6d0ea02b7286cc7e74ec951d1c9822c38576feb73bc"
      ],
      [
        "8c00fa9b18ebf331eb961537a45a4266c7034f2f0d4e1d0716fb6eae20eae29e",
        "efa47267fea521a1a9dc343a3736c974c2fadafa81e36c54e7d2a4c66702414b"
      ],
      [
        "e7a26ce69dd4829f3e10cec0a9e98ed3143d084f308b92c0997fddfc60cb3e41",
        "2a758e300fa7984b471b006a1aafbb18d0a6b2c0420e83e20e8a9421cf2cfd51"
      ],
      [
        "b6459e0ee3662ec8d23540c223bcbdc571cbcb967d79424f3cf29eb3de6b80ef",
        "067c876d06f3e06de1dadf16e5661db3c4b3ae6d48e35b2ff30bf0b61a71ba45"
      ],
      [
        "d68a80c8280bb840793234aa118f06231d6f1fc67e73c5a5deda0f5b496943e8",
        "db8ba9fff4b586d00c4b1f9177b0e28b5b0e7b8f7845295a294c84266b133120"
      ],
      [
        "324aed7df65c804252dc0270907a30b09612aeb973449cea4095980fc28d3d5d",
        "648a365774b61f2ff130c0c35aec1f4f19213b0c7e332843967224af96ab7c84"
      ],
      [
        "4df9c14919cde61f6d51dfdbe5fee5dceec4143ba8d1ca888e8bd373fd054c96",
        "35ec51092d8728050974c23a1d85d4b5d506cdc288490192ebac06cad10d5d"
      ],
      [
        "9c3919a84a474870faed8a9c1cc66021523489054d7f0308cbfc99c8ac1f98cd",
        "ddb84f0f4a4ddd57584f044bf260e641905326f76c64c8e6be7e5e03d4fc599d"
      ],
      [
        "6057170b1dd12fdf8de05f281d8e06bb91e1493a8b91d4cc5a21382120a959e5",
        "9a1af0b26a6a4807add9a2daf71df262465152bc3ee24c65e899be932385a2a8"
      ],
      [
        "a576df8e23a08411421439a4518da31880cef0fba7d4df12b1a6973eecb94266",
        "40a6bf20e76640b2c92b97afe58cd82c432e10a7f514d9f3ee8be11ae1b28ec8"
      ],
      [
        "7778a78c28dec3e30a05fe9629de8c38bb30d1f5cf9a3a208f763889be58ad71",
        "34626d9ab5a5b22ff7098e12f2ff580087b38411ff24ac563b513fc1fd9f43ac"
      ],
      [
        "0928955ee637a84463729fd30e7afd2ed5f96274e5ad7e5cb09eda9c06d903ac",
        "c25621003d3f42a827b78a13093a95eeac3d26efa8a8d83fc5180e935bcd091f"
      ],
      [
        "85d0fef3ec6db109399064f3a0e3b2855645b4a907ad354527aae75163d82751",
        "1f03648413a38c0be29d496e582cf5663e8751e96877331582c237a24eb1f962"
      ],
      [
        "ff2b0dce97eece97c1c9b6041798b85dfdfb6d8882da20308f5404824526087e",
        "493d13fef524ba188af4c4dc54d07936c7b7ed6fb90e2ceb2c951e01f0c29907"
      ],
      [
        "827fbbe4b1e880ea9ed2b2e6301b212b57f1ee148cd6dd28780e5e2cf856e241",
        "c60f9c923c727b0b71bef2c67d1d12687ff7a63186903166d605b68baec293ec"
      ],
      [
        "eaa649f21f51bdbae7be4ae34ce6e5217a58fdce7f47f9aa7f3b58fa2120e2b3",
        "be3279ed5bbbb03ac69a80f89879aa5a01a6b965f13f7e59d47a5305ba5ad93d"
      ],
      [
        "e4a42d43c5cf169d9391df6decf42ee541b6d8f0c9a137401e23632dda34d24f",
        "4d9f92e716d1c73526fc99ccfb8ad34ce886eedfa8d8e4f13a7f7131deba9414"
      ],
      [
        "1ec80fef360cbdd954160fadab352b6b92b53576a88fea4947173b9d4300bf19",
        "aeefe93756b5340d2f3a4958a7abbf5e0146e77f6295a07b671cdc1cc107cefd"
      ],
      [
        "146a778c04670c2f91b00af4680dfa8bce3490717d58ba889ddb5928366642be",
        "b318e0ec3354028add669827f9d4b2870aaa971d2f7e5ed1d0b297483d83efd0"
      ],
      [
        "fa50c0f61d22e5f07e3acebb1aa07b128d0012209a28b9776d76a8793180eef9",
        "6b84c6922397eba9b72cd2872281a68a5e683293a57a213b38cd8d7d3f4f2811"
      ],
      [
        "da1d61d0ca721a11b1a5bf6b7d88e8421a288ab5d5bba5220e53d32b5f067ec2",
        "8157f55a7c99306c79c0766161c91e2966a73899d279b48a655fba0f1ad836f1"
      ],
      [
        "a8e282ff0c9706907215ff98e8fd416615311de0446f1e062a73b0610d064e13",
        "7f97355b8db81c09abfb7f3c5b2515888b679a3e50dd6bd6cef7c73111f4cc0c"
      ],
      [
        "174a53b9c9a285872d39e56e6913cab15d59b1fa512508c022f382de8319497c",
        "ccc9dc37abfc9c1657b4155f2c47f9e6646b3a1d8cb9854383da13ac079afa73"
      ],
      [
        "959396981943785c3d3e57edf5018cdbe039e730e4918b3d884fdff09475b7ba",
        "2e7e552888c331dd8ba0386a4b9cd6849c653f64c8709385e9b8abf87524f2fd"
      ],
      [
        "d2a63a50ae401e56d645a1153b109a8fcca0a43d561fba2dbb51340c9d82b151",
        "e82d86fb6443fcb7565aee58b2948220a70f750af484ca52d4142174dcf89405"
      ],
      [
        "64587e2335471eb890ee7896d7cfdc866bacbdbd3839317b3436f9b45617e073",
        "d99fcdd5bf6902e2ae96dd6447c299a185b90a39133aeab358299e5e9faf6589"
      ],
      [
        "8481bde0e4e4d885b3a546d3e549de042f0aa6cea250e7fd358d6c86dd45e458",
        "38ee7b8cba5404dd84a25bf39cecb2ca900a79c42b262e556d64b1b59779057e"
      ],
      [
        "13464a57a78102aa62b6979ae817f4637ffcfed3c4b1ce30bcd6303f6caf666b",
        "69be159004614580ef7e433453ccb0ca48f300a81d0942e13f495a907f6ecc27"
      ],
      [
        "bc4a9df5b713fe2e9aef430bcc1dc97a0cd9ccede2f28588cada3a0d2d83f366",
        "0d3a81ca6e785c06383937adf4b798caa6e8a9fbfa547b16d758d666581f33c1"
      ],
      [
        "8c28a97bf8298bc0d23d8c749452a32e694b65e30a9472a3954ab30fe5324caa",
        "40a30463a3305193378fedf31f7cc0eb7ae784f0451cb9459e71dc73cbef9482"
      ],
      [
        "08ea9666139527a8c1dd94ce4f071fd23c8b350c5a4bb33748c4ba111faccae0",
        "620efabbc8ee2782e24e7c0cfb95c5d735b783be9cf0f8e955af34a30e62b945"
      ],
      [
        "dd3625faef5ba06074669716bbd3788d89bdde815959968092f76cc4eb9a9787",
        "7a188fa3520e30d461da2501045731ca941461982883395937f68d00c644a573"
      ],
      [
        "f710d79d9eb962297e4f6232b40e8f7feb2bc63814614d692c12de752408221e",
        "ea98e67232d3b3295d3b535532115ccac8612c721851617526ae47a9c77bfc82"
      ]
    ]
  }
};
}],
[/* 44 */ 'hsd', '/lib/protocol/network.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * network.js - network object for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = __node_require__(2 /* 'bsert' */);
const binary = __node_require__(45 /* '../utils/binary' */);
const networks = __node_require__(46 /* './networks' */);
const TimeData = __node_require__(49 /* './timedata' */);

/**
 * Network
 * Represents a network.
 * @alias module:protocol.Network
 */

class Network {
  /**
   * Create a network.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    assert(!Network[options.type], 'Cannot create two networks.');

    this.type = options.type;
    this.seeds = options.seeds;
    this.magic = options.magic;
    this.port = options.port;
    this.brontidePort = options.brontidePort;
    this.checkpointMap = options.checkpointMap;
    this.lastCheckpoint = options.lastCheckpoint;
    this.checkpoints = [];
    this.halvingInterval = options.halvingInterval;
    this.coinbaseMaturity = options.coinbaseMaturity;
    this.genesis = options.genesis;
    this.genesisBlock = options.genesisBlock;
    this.pow = options.pow;
    this.names = options.names;
    this.goosigStop = options.goosigStop;
    this.block = options.block;
    this.activationThreshold = options.activationThreshold;
    this.minerWindow = options.minerWindow;
    this.deployments = options.deployments;
    this.deploys = options.deploys;
    this.unknownBits = 0;
    this.keyPrefix = options.keyPrefix;
    this.addressPrefix = options.addressPrefix;
    this.requireStandard = options.requireStandard;
    this.rpcPort = options.rpcPort;
    this.walletPort = options.walletPort;
    this.nsPort = options.nsPort;
    this.rsPort = options.rsPort;
    this.minRelay = options.minRelay;
    this.feeRate = options.feeRate;
    this.maxFeeRate = options.maxFeeRate;
    this.identityKey = options.identityKey;
    this.selfConnect = options.selfConnect;
    this.requestMempool = options.requestMempool;
    this.claimPrefix = options.claimPrefix;
    this.deflationHeight = options.deflationHeight;
    this.time = new TimeData();
    this.txStart = options.txStart;

    this.init();
  }

  /**
   * Get a deployment by bit index.
   * @param {Number} bit
   * @returns {Object}
   */

  init() {
    let bits = 0;

    for (const deployment of this.deploys)
      bits |= 1 << deployment.bit;

    this.unknownBits = ~bits >>> 0;

    for (const key of Object.keys(this.checkpointMap)) {
      const hash = this.checkpointMap[key];
      const height = Number(key);

      this.checkpoints.push({ hash, height });
    }

    this.checkpoints.sort(cmpNode);
  }

  /**
   * Get a deployment by bit index.
   * @param {Number} bit
   * @returns {Object}
   */

  byBit(bit) {
    const index = binary.search(this.deploys, bit, cmpBit);

    if (index === -1)
      return null;

    return this.deploys[index];
  }

  /**
   * Get network adjusted time.
   * @returns {Number}
   */

  now() {
    return this.time.now();
  }

  /**
   * Get network adjusted time in milliseconds.
   * @returns {Number}
   */

  ms() {
    return this.time.ms();
  }

  /**
   * Create a network. Get existing network if possible.
   * @param {NetworkType|Object} options
   * @returns {Network}
   */

  static create(options) {
    if (typeof options === 'string')
      options = networks[options];

    assert(options, 'Unknown network.');

    if (Network[options.type])
      return Network[options.type];

    const network = new Network(options);

    Network[network.type] = network;

    if (!Network.primary)
      Network.primary = network;

    return network;
  }

  /**
   * Set the default network. This network will be used
   * if nothing is passed as the `network` option for
   * certain objects.
   * @param {NetworkType} type - Network type.
   * @returns {Network}
   */

  static set(type) {
    assert(typeof type === 'string', 'Bad network.');
    Network.primary = Network.get(type);
    Network.type = type;
    return Network.primary;
  }

  /**
   * Get a network with a string or a Network object.
   * @param {NetworkType|Network} type - Network type.
   * @returns {Network}
   */

  static get(type) {
    if (!type) {
      assert(Network.primary, 'No default network.');
      return Network.primary;
    }

    if (type instanceof Network)
      return type;

    if (typeof type === 'string')
      return Network.create(type);

    throw new Error('Unknown network.');
  }

  /**
   * Get a network with a string or a Network object.
   * @param {NetworkType|Network} type - Network type.
   * @returns {Network}
   */

  static ensure(type) {
    if (!type) {
      assert(Network.primary, 'No default network.');
      return Network.primary;
    }

    if (type instanceof Network)
      return type;

    if (typeof type === 'string') {
      if (networks[type])
        return Network.create(type);
    }

    assert(Network.primary, 'No default network.');

    return Network.primary;
  }

  /**
   * Get a network by an associated comparator.
   * @private
   * @param {Object} value
   * @param {Function} compare
   * @param {Network|null} network
   * @param {String} name
   * @returns {Network}
   */

  static by(value, compare, network, name) {
    if (network) {
      network = Network.get(network);
      if (compare(network, value))
        return network;
      throw new Error(`Network mismatch for ${name}.`);
    }

    for (const type of networks.types) {
      network = networks[type];
      if (compare(network, value))
        return Network.get(type);
    }

    throw new Error(`Network not found for ${name}.`);
  }

  /**
   * Get a network by its magic number.
   * @param {Number} value
   * @param {Network?} network
   * @returns {Network}
   */

  static fromMagic(value, network) {
    return Network.by(value, cmpMagic, network, 'magic number');
  }

  /**
   * Get a network by its WIF prefix.
   * @param {Number} value
   * @param {Network?} network
   * @returns {Network}
   */

  static fromWIF(prefix, network) {
    return Network.by(prefix, cmpWIF, network, 'WIF');
  }

  /**
   * Get a network by its xpubkey prefix.
   * @param {Number} value
   * @param {Network?} network
   * @returns {Network}
   */

  static fromPublic(prefix, network) {
    return Network.by(prefix, cmpPub, network, 'xpubkey');
  }

  /**
   * Get a network by its xprivkey prefix.
   * @param {Number} value
   * @param {Network?} network
   * @returns {Network}
   */

  static fromPrivate(prefix, network) {
    return Network.by(prefix, cmpPriv, network, 'xprivkey');
  }

  /**
   * Get a network by its xpubkey base58 prefix.
   * @param {String} prefix
   * @param {Network?} network
   * @returns {Network}
   */

  static fromPublic58(prefix, network) {
    return Network.by(prefix, cmpPub58, network, 'xpubkey');
  }

  /**
   * Get a network by its xprivkey base58 prefix.
   * @param {String} prefix
   * @param {Network?} network
   * @returns {Network}
   */

  static fromPrivate58(prefix, network) {
    return Network.by(prefix, cmpPriv58, network, 'xprivkey');
  }

  /**
   * Get a network by its bech32 address prefix.
   * @param {String} hrp
   * @param {Network?} network
   * @returns {Network}
   */

  static fromAddress(hrp, network) {
    return Network.by(hrp, cmpAddress, network, 'address');
  }

  /**
   * Convert the network to a string.
   * @returns {String}
   */

  toString() {
    return this.type;
  }

  /**
   * Inspect the network.
   * @returns {String}
   */

  inspect() {
    return `<Network: ${this.type}>`;
  }

  /**
   * Test an object to see if it is a Network.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isNetwork(obj) {
    return obj instanceof Network;
  }
}

/**
 * Default network.
 * @type {Network}
 */

Network.primary = null;

/**
 * Default network type.
 * @type {String}
 */

Network.type = null;

/*
 * Networks (to avoid hash table mode).
 */

Network.main = null;
Network.testnet = null;
Network.regtest = null;
Network.segnet4 = null;
Network.simnet = null;

/*
 * Set initial network.
 */

Network.set(process.env.HSD_NETWORK || 'main');

/*
 * Helpers
 */

function cmpBit(a, b) {
  return a.bit - b;
}

function cmpNode(a, b) {
  return a.height - b.height;
}

function cmpMagic(network, magic) {
  return network.magic === magic;
}

function cmpWIF(network, prefix) {
  return network.keyPrefix.privkey === prefix;
}

function cmpPub(network, prefix) {
  return network.keyPrefix.xpubkey === prefix;
}

function cmpPriv(network, prefix) {
  return network.keyPrefix.xprivkey === prefix;
}

function cmpPub58(network, prefix) {
  return network.keyPrefix.xpubkey58 === prefix;
}

function cmpPriv58(network, prefix) {
  return network.keyPrefix.xprivkey58 === prefix;
}

function cmpAddress(network, hrp) {
  return network.addressPrefix === hrp;
}

/*
 * Expose
 */

module.exports = Network;
}],
[/* 45 */ 'hsd', '/lib/utils/binary.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * binary.js - binary search utils for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

/**
 * Perform a binary search on a sorted array.
 * @param {Array} items
 * @param {Object} key
 * @param {Function} compare
 * @param {Boolean?} insert
 * @returns {Number} Index.
 */

exports.search = function search(items, key, compare, insert) {
  let start = 0;
  let end = items.length - 1;

  while (start <= end) {
    const pos = (start + end) >>> 1;
    const cmp = compare(items[pos], key);

    if (cmp === 0)
      return pos;

    if (cmp < 0)
      start = pos + 1;
    else
      end = pos - 1;
  }

  if (!insert)
    return -1;

  return start;
};

/**
 * Perform a binary insert on a sorted array.
 * @param {Array} items
 * @param {Object} item
 * @param {Function} compare
 * @returns {Number} index
 */

exports.insert = function insert(items, item, compare, uniq) {
  const i = exports.search(items, item, compare, true);

  if (uniq && i < items.length) {
    if (compare(items[i], item) === 0)
      return -1;
  }

  if (i === 0)
    items.unshift(item);
  else if (i === items.length)
    items.push(item);
  else
    items.splice(i, 0, item);

  return i;
};

/**
 * Perform a binary removal on a sorted array.
 * @param {Array} items
 * @param {Object} item
 * @param {Function} compare
 * @returns {Boolean}
 */

exports.remove = function remove(items, item, compare) {
  const i = exports.search(items, item, compare, false);

  if (i === -1)
    return false;

  splice(items, i);

  return true;
};

/*
 * Helpers
 */

function splice(list, i) {
  if (i === 0) {
    list.shift();
    return;
  }

  let k = i + 1;

  while (k < list.length)
    list[i++] = list[k++];

  list.pop();
}
}],
[/* 46 */ 'hsd', '/lib/protocol/networks.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * network.js - handshake networks for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

/* eslint no-implicit-coercion: "off" */

'use strict';

/**
 * @module protocol/networks
 */

const BN = __node_require__(31 /* 'bcrypto/lib/bn.js' */);
const genesis = __node_require__(47 /* './genesis' */);
const network = exports;

/**
 * Network type list.
 * @memberof module:protocol/networks
 * @const {String[]}
 * @default
 */

network.types = ['main', 'testnet', 'regtest', 'simnet'];

/**
 * Mainnet
 * @static
 * @lends module:protocol/networks
 * @type {Object}
 */

const main = {};

/**
 * Symbolic network type.
 * @const {String}
 * @default
 */

main.type = 'main';

/**
 * Default DNS seeds.
 * @const {String[]}
 * @default
 */

main.seeds = [
  'hs-mainnet.bcoin.ninja', // Christopher Jeffrey
  'seed.easyhandshake.com' // Matthew Zipkin
];

/**
 * Packet magic number.
 * @const {Number}
 * @default
 */

main.magic = genesis.main.magic;

/**
 * Default network port.
 * @const {Number}
 * @default
 */

main.port = 12038;

/**
 * Default brontide port.
 * @const {Number}
 * @default
 */

main.brontidePort = 44806;

/**
 * Checkpoint block list.
 * @const {Object}
 */

main.checkpointMap = {
  1008: Buffer.from(
    '0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e', 'hex'),
  2016: Buffer.from(
    '0000000000000424ee6c2a5d6e0da5edfc47a4a10328c1792056ee48303c3e40', 'hex'),
  10000: Buffer.from(
    '00000000000001a86811a6f520bf67cefa03207dc84fd315f58153b28694ec51', 'hex'),
  20000: Buffer.from(
    '0000000000000162c7ac70a582256f59c189b5c90d8e9861b3f374ed714c58de', 'hex'),
  30000: Buffer.from(
    '0000000000000004f790862846b23c3a81585aea0fa79a7d851b409e027bcaa7', 'hex'),
  40000: Buffer.from(
    '0000000000000002966206a40b10a575cb46531253b08dae8e1b356cfa277248', 'hex'),
  50000: Buffer.from(
    '00000000000000020c7447e7139feeb90549bfc77a7f18d4ff28f327c04f8d6e', 'hex'),
  56880: Buffer.from(
    '0000000000000001d4ef9ea6908bb4eb970d556bd07cbd7d06a634e1cd5bbf4e', 'hex'),
  61043: Buffer.from(
    '00000000000000015b84385e0307370f8323420eaa27ef6e407f2d3162f1fd05', 'hex')
};

/**
 * Last checkpoint height.
 * @const {Number}
 * @default
 */

main.lastCheckpoint = 61043;

/**
 * Reward halving interval.
 * Roughly every 3.25 years.
 * @const {Number}
 * @default
 */

main.halvingInterval = 170000;

/**
 * Number of blocks before a coinbase
 * spend can occur (consensus).
 * @const {Number}
 * @default
 */

main.coinbaseMaturity = 100;

/**
 * Genesis block header.
 * @const {Object}
 */

main.genesis = genesis.main;

/**
 * The network's genesis block in a hex string.
 * @const {String}
 */

main.genesisBlock = genesis.mainData;

/**
 * POW-related constants.
 * @enum {Number}
 * @default
 */

main.pow = {};

/**
 * Default target.
 * @const {BN}
 */

main.pow.limit = new BN(
  '0000000000ffff00000000000000000000000000000000000000000000000000',
  'hex'
);

/**
 * Compact pow limit.
 * @const {Number}
 * @default
 */

main.pow.bits = 0x1c00ffff;

/**
 * Minimum chainwork for best chain.
 * @const {BN}
 */

main.pow.chainwork = new BN(
  '00000000000000000000000000000000000000000000000075b5a2b7bf522d45',
  'hex'
);

/**
 * Retarget window in blocks.
 * @const {Number}
 * @default
 */

main.pow.targetWindow = 144;

/**
 * Average block time.
 * @const {Number}
 * @default
 */

main.pow.targetSpacing = 10 * 60;

/**
 * Average blocks per day.
 * @const {Number}
 * @default
 */

main.pow.blocksPerDay = ((24 * 60 * 60) / main.pow.targetSpacing) >>> 0;

/**
 * Desired retarget period in seconds.
 * @const {Number}
 * @default
 */

main.pow.targetTimespan = main.pow.targetWindow * main.pow.targetSpacing;

/**
 * Minimum actual time.
 * @const {Number}
 * @default
 */

main.pow.minActual = (main.pow.targetTimespan / 4) >>> 0;

/**
 * Maximum actual time.
 * @const {Number}
 * @default
 */

main.pow.maxActual = main.pow.targetTimespan * 4;

/**
 * Whether to reset target if a block
 * has not been mined recently.
 * @const {Boolean}
 * @default
 */

main.pow.targetReset = false;

/**
 * Do not allow retargetting.
 * @const {Boolean}
 * @default
 */

main.pow.noRetargeting = false;

/**
 * Prohibit all transactions until
 * sufficient chainwork has been accumulated.
 * @const {Number}
 */

main.txStart = 14 * main.pow.blocksPerDay;

/**
 * Name-related constants.
 * @enum {Number}
 * @default
 */

main.names = {
  /**
   * Height at which the auction system activates.
   * Must be greater or equal to txStart.
   * @const {Number}
   */

  auctionStart: 14 * main.pow.blocksPerDay,

  /**
   * Interval at which names are rolled out.
   * @const {Number}
   */

  rolloutInterval: 7 * main.pow.blocksPerDay,

  /**
   * Amount of time a name is locked for after being claimed.
   * @const {Number}
   */

  lockupPeriod: 30 * main.pow.blocksPerDay,

  /**
   * Time period after which names expire.
   * @const {Number}
   */

  renewalWindow: (2 * 365) * main.pow.blocksPerDay,

  /**
   * Committed renewal block hashes
   * must be no older than this.
   * @const {Number}
   */

  renewalPeriod: 182 * main.pow.blocksPerDay,

  /**
   * Committed renewal block hashes
   * must be at least this old.
   * @const {Number}
   */

  renewalMaturity: 30 * main.pow.blocksPerDay,

  /**
   * The time window in which the
   * nameholders can claim reserved names.
   * @const {Number}
   */

  claimPeriod: (4 * 365) * main.pow.blocksPerDay,

  /**
   * Amount of time required in between
   * replacement claims.
   * @const {Number}
   */

  claimFrequency: 2 * main.pow.blocksPerDay,

  /**
   * Bidding time period.
   * @const {Number}
   */

  biddingPeriod: 5 * main.pow.blocksPerDay,

  /**
   * Reveal time period.
   * @const {Number}
   */

  revealPeriod: 10 * main.pow.blocksPerDay,

  /**
   * Interval at which the name tree is updated.
   * @const {Number}
   */

  treeInterval: main.pow.blocksPerDay >>> 2,

  /**
   * Amount of time transfers are locked up for.
   * @const {Number}
   */

  transferLockup: 2 * main.pow.blocksPerDay,

  /**
   * Amount of time before a transfer
   * or revocation is possible.
   * @const {Number}
   */

  revocationDelay: 14 * main.pow.blocksPerDay,

  /**
   * Sum of total period and revocation delay.
   * @const {Number}
   */

  auctionMaturity: (5 + 10 + 14) * main.pow.blocksPerDay,

  /**
   * Whether there is no weekly rollout.
   * @const {Boolean}
   */

  noRollout: false,

  /**
   * Whether there are no names reserved.
   * @const {Boolean}
   */

  noReserved: false
};

/**
 * Block constants.
 * @enum {Number}
 * @default
 */

main.block = {
  /**
   * Safe height to start pruning.
   */

  pruneAfterHeight: 1000,

  /**
   * Safe number of blocks to keep.
   */

  keepBlocks: 288,

  /**
   * Age used for the time delta to
   * determine whether the chain is synced.
   */

  maxTipAge: 12 * 60 * 60,

  /**
   * Height at which block processing is
   * slow enough that we can output
   * logs without spamming.
   */

  slowHeight: 0
};

/**
 * Block height at which GooSig claims are
 * disabled. This limits risk associated
 * with newly discovered cryptography
 * attacks or social engineering attacks.
 *
 * Estimated to be disabled at 1 year +
 * 1 month from the start of the network
 * on mainnet.
 */

main.goosigStop = (365 + 30) * main.pow.blocksPerDay;

/**
 * For versionbits.
 * @const {Number}
 * @default
 */

main.activationThreshold = 1916;

/**
 * Confirmation window for versionbits.
 * @const {Number}
 * @default
 */

main.minerWindow = 2016;

/**
 * Deployments for versionbits.
 * @const {Object}
 * @default
 */

main.deployments = {
  hardening: {
    name: 'hardening',
    bit: 0,
    startTime: 1581638400, // February 14th, 2020
    timeout: 1707868800, // February 14th, 2024
    threshold: -1,
    window: -1,
    required: false,
    force: false
  },
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 1199145601, // January 1, 2008
    timeout: 1230767999, // December 31, 2008
    threshold: -1,
    window: -1,
    required: false,
    force: true
  }
};

/**
 * Deployments for versionbits (array form, sorted).
 * @const {Array}
 * @default
 */

main.deploys = [
  main.deployments.hardening,
  main.deployments.testdummy
];

/**
 * Key prefixes.
 * @enum {Number}
 * @default
 */

main.keyPrefix = {
  privkey: 0x80,
  xpubkey: 0x0488b21e,
  xprivkey: 0x0488ade4,
  xpubkey58: 'xpub',
  xprivkey58: 'xprv',
  coinType: 5353
};

/**
 * Address prefix.
 * @const {String}
 */

main.addressPrefix = 'hs';

/**
 * Default value for whether the mempool
 * accepts non-standard transactions.
 * @const {Boolean}
 * @default
 */

main.requireStandard = true;

/**
 * Default http port.
 * @const {Number}
 * @default
 */

main.rpcPort = 12037;

/**
 * Default wallet port.
 * @const {Number}
 * @default
 */

main.walletPort = 12039;

/**
 * Default DNS port.
 * @const {Number}
 * @default
 */

main.nsPort = 5349;

/**
 * Default recursive DNS port.
 * @const {Number}
 * @default
 */

main.rsPort = 5350;

/**
 * Default min relay rate.
 * @const {Rate}
 * @default
 */

main.minRelay = 1000;

/**
 * Default normal relay rate.
 * @const {Rate}
 * @default
 */

main.feeRate = 100000;

/**
 * Maximum normal relay rate.
 * @const {Rate}
 * @default
 */

main.maxFeeRate = 400000;

/**
 * Default identity key (testing only).
 * @const {Buffer|null}
 * @default
 */

main.identityKey = null;

/**
 * Whether to allow self-connection.
 * @const {Boolean}
 */

main.selfConnect = false;

/**
 * Whether to request mempool on sync.
 * @const {Boolean}
 */

main.requestMempool = false;

/**
 * DNSSEC ownership prefix.
 * @const {String}
 */

main.claimPrefix = 'hns-claim:';

/**
 * Activation height for inflation bug fix.
 * @const {Number}
 */

main.deflationHeight = 61043;

/*
 * Testnet
 */

const testnet = {};

testnet.type = 'testnet';

testnet.seeds = [
  'hs-testnet.bcoin.ninja' // Christopher Jeffrey
];

testnet.magic = genesis.testnet.magic;

testnet.port = 13038;

testnet.brontidePort = 45806;

testnet.checkpointMap = {};

testnet.lastCheckpoint = 0;

testnet.halvingInterval = 170000;
testnet.coinbaseMaturity = 100;

testnet.genesis = genesis.testnet;
testnet.genesisBlock = genesis.testnetData;

testnet.pow = {};

// Probably minable very quick with 1 GPU.
testnet.pow.limit = new BN(
  '00000000ffff0000000000000000000000000000000000000000000000000000',
  'hex'
);
testnet.pow.bits = 0x1d00ffff;
testnet.pow.chainwork = new BN(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
testnet.pow.targetWindow = 144;
testnet.pow.targetSpacing = 10 * 60;
testnet.pow.blocksPerDay = ((24 * 60 * 60) / testnet.pow.targetSpacing) >>> 0;
testnet.pow.targetTimespan =
  testnet.pow.targetWindow * testnet.pow.targetSpacing;
testnet.pow.minActual = (testnet.pow.targetTimespan / 4) >>> 0;
testnet.pow.maxActual = testnet.pow.targetTimespan * 4;
testnet.pow.targetReset = true;
testnet.pow.noRetargeting = false;
testnet.txStart = 0;

testnet.names = {
  auctionStart: (0.25 * testnet.pow.blocksPerDay) | 0,
  rolloutInterval: (0.25 * testnet.pow.blocksPerDay) | 0,
  lockupPeriod: (0.25 * testnet.pow.blocksPerDay) | 0,
  renewalWindow: 30 * testnet.pow.blocksPerDay,
  renewalPeriod: 7 * testnet.pow.blocksPerDay,
  renewalMaturity: 1 * testnet.pow.blocksPerDay,
  claimPeriod: 90 * testnet.pow.blocksPerDay,
  claimFrequency: 2 * testnet.pow.blocksPerDay,
  biddingPeriod: 1 * testnet.pow.blocksPerDay,
  revealPeriod: 2 * testnet.pow.blocksPerDay,
  treeInterval: testnet.pow.blocksPerDay >>> 2,
  transferLockup: 2 * testnet.pow.blocksPerDay,
  revocationDelay: 4 * testnet.pow.blocksPerDay,
  auctionMaturity: (1 + 2 + 4) * testnet.pow.blocksPerDay,
  noRollout: false,
  noReserved: false
};

testnet.block = {
  pruneAfterHeight: 1000,
  keepBlocks: 10000,
  maxTipAge: 12 * 60 * 60,
  slowHeight: 0
};

testnet.goosigStop = 20 * testnet.pow.blocksPerDay;

testnet.activationThreshold = 1512;

testnet.minerWindow = 2016;

testnet.deployments = {
  hardening: {
    name: 'hardening',
    bit: 0,
    startTime: 1581638400, // February 14th, 2020
    timeout: 1707868800, // February 14th, 2024
    threshold: -1,
    window: -1,
    required: false,
    force: false
  },
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 1199145601, // January 1, 2008
    timeout: 1230767999, // December 31, 2008
    threshold: -1,
    window: -1,
    required: false,
    force: true
  }
};

testnet.deploys = [
  testnet.deployments.hardening,
  testnet.deployments.testdummy
];

testnet.keyPrefix = {
  privkey: 0xef,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  xpubkey58: 'tpub',
  xprivkey58: 'tprv',
  coinType: 5354
};

testnet.addressPrefix = 'ts';

testnet.requireStandard = false;

testnet.rpcPort = 13037;

testnet.walletPort = 13039;

testnet.nsPort = 15349;

testnet.rsPort = 15350;

testnet.minRelay = 1000;

testnet.feeRate = 20000;

testnet.maxFeeRate = 60000;

testnet.identityKey = null;

testnet.selfConnect = false;

testnet.requestMempool = false;

testnet.claimPrefix = 'hns-testnet:';

testnet.deflationHeight = 0;

/*
 * Regtest
 */

const regtest = {};

regtest.type = 'regtest';

regtest.seeds = [];

regtest.magic = genesis.regtest.magic;

regtest.port = 14038;

regtest.brontidePort = 46806;

regtest.checkpointMap = {};
regtest.lastCheckpoint = 0;

regtest.halvingInterval = 2500;
regtest.coinbaseMaturity = 2;

regtest.genesis = genesis.regtest;
regtest.genesisBlock = genesis.regtestData;

regtest.pow = {};
regtest.pow.limit = new BN(
  '7fffff0000000000000000000000000000000000000000000000000000000000',
  'hex'
);
regtest.pow.bits = 0x207fffff;
regtest.pow.chainwork = new BN(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
regtest.pow.targetWindow = 144;
regtest.pow.targetSpacing = 10 * 60;
regtest.pow.blocksPerDay = ((24 * 60 * 60) / regtest.pow.targetSpacing) >>> 0;
regtest.pow.targetTimespan =
  regtest.pow.targetWindow * regtest.pow.targetSpacing;
regtest.pow.minActual = (regtest.pow.targetTimespan / 4) >>> 0;
regtest.pow.maxActual = regtest.pow.targetTimespan * 4;
regtest.pow.targetReset = true;
regtest.pow.noRetargeting = true;
regtest.txStart = 0;

regtest.names = {
  auctionStart: 0,
  rolloutInterval: 2,
  lockupPeriod: 2,
  renewalWindow: 5000,
  renewalPeriod: 2500,
  renewalMaturity: 50,
  claimPeriod: 250000,
  claimFrequency: 0,
  biddingPeriod: 5,
  revealPeriod: 10,
  treeInterval: 5,
  transferLockup: 10,
  revocationDelay: 50,
  auctionMaturity: 5 + 10 + 50,
  noRollout: false,
  noReserved: false
};

regtest.block = {
  pruneAfterHeight: 1000,
  keepBlocks: 10000,
  maxTipAge: 0xffffffff,
  slowHeight: 0
};

regtest.goosigStop = -1 >>> 0;

regtest.activationThreshold = 108;

regtest.minerWindow = 144;

regtest.deployments = {
  hardening: {
    name: 'hardening',
    bit: 0,
    startTime: 1581638400, // February 14th, 2020
    timeout: 1707868800, // February 14th, 2024
    threshold: -1,
    window: -1,
    required: false,
    force: false
  },
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 0,
    timeout: 0xffffffff,
    threshold: -1,
    window: -1,
    required: false,
    force: true
  }
};

regtest.deploys = [
  regtest.deployments.hardening,
  regtest.deployments.testdummy
];

regtest.keyPrefix = {
  privkey: 0x5a,
  xpubkey: 0xeab4fa05,
  xprivkey: 0xeab404c7,
  xpubkey58: 'rpub',
  xprivkey58: 'rprv',
  coinType: 5355
};

regtest.addressPrefix = 'rs';

regtest.requireStandard = false;

regtest.rpcPort = 14037;

regtest.walletPort = 14039;

regtest.nsPort = 25349;

regtest.rsPort = 25350;

regtest.minRelay = 1000;

regtest.feeRate = 20000;

regtest.maxFeeRate = 60000;

regtest.identityKey = Buffer.from(
  '104932181cfed7584105c728cdc0eb9af1e7ffdc4a00743fd45e5de66cac7668',
  'hex'
);

regtest.selfConnect = true;

regtest.requestMempool = true;

regtest.claimPrefix = 'hns-regtest:';

regtest.deflationHeight = 200;

/*
 * Simnet
 */

const simnet = {};

simnet.type = 'simnet';

simnet.seeds = [];

simnet.magic = genesis.simnet.magic;

simnet.port = 15038;

simnet.brontidePort = 47806;

simnet.checkpointMap = {};

simnet.lastCheckpoint = 0;

simnet.halvingInterval = 170000;
simnet.coinbaseMaturity = 6;

simnet.genesis = genesis.simnet;
simnet.genesisBlock = genesis.simnetData;

simnet.pow = {};
simnet.pow.limit = new BN(
  '7fffff0000000000000000000000000000000000000000000000000000000000',
  'hex'
);
simnet.pow.bits = 0x207fffff;
simnet.pow.chainwork = new BN(
  '0000000000000000000000000000000000000000000000000000000000000000',
  'hex'
);
simnet.pow.targetWindow = 144;
simnet.pow.targetSpacing = 10 * 60;
simnet.pow.blocksPerDay = ((24 * 60 * 60) / simnet.pow.targetSpacing) >>> 0;
simnet.pow.targetTimespan =
  simnet.pow.targetWindow * simnet.pow.targetSpacing;
simnet.pow.minActual = (simnet.pow.targetTimespan / 4) >>> 0;
simnet.pow.maxActual = simnet.pow.targetTimespan * 4;
simnet.pow.targetReset = false;
simnet.pow.noRetargeting = false;
simnet.txStart = 0;

simnet.names = {
  auctionStart: 0,
  rolloutInterval: 1,
  lockupPeriod: 1,
  renewalWindow: 2500,
  renewalPeriod: 1250,
  renewalMaturity: 25,
  claimPeriod: 75000,
  claimFrequency: 0,
  biddingPeriod: 25,
  revealPeriod: 50,
  treeInterval: 2,
  transferLockup: 5,
  revocationDelay: 25,
  auctionMaturity: 25 + 50 + 25,
  noRollout: false,
  noReserved: false
};

simnet.block = {
  pruneAfterHeight: 1000,
  keepBlocks: 10000,
  maxTipAge: 0xffffffff,
  slowHeight: 0
};

simnet.goosigStop = -1 >>> 0;

simnet.activationThreshold = 75;

simnet.minerWindow = 100;

simnet.deployments = {
  hardening: {
    name: 'hardening',
    bit: 0,
    startTime: 1581638400, // February 14th, 2020
    timeout: 1707868800, // February 14th, 2024
    threshold: -1,
    window: -1,
    required: false,
    force: false
  },
  testdummy: {
    name: 'testdummy',
    bit: 28,
    startTime: 1199145601, // January 1, 2008
    timeout: 1230767999, // December 31, 2008
    threshold: -1,
    window: -1,
    required: false,
    force: true
  }
};

simnet.deploys = [
  simnet.deployments.hardening,
  simnet.deployments.testdummy
];

simnet.keyPrefix = {
  privkey: 0x64,
  xpubkey: 0x0420bd3a,
  xprivkey: 0x0420b900,
  xpubkey58: 'spub',
  xprivkey58: 'sprv',
  coinType: 5356
};

simnet.addressPrefix = 'ss';

simnet.requireStandard = false;

simnet.rpcPort = 15037;

simnet.walletPort = 15039;

simnet.nsPort = 35349;

simnet.rsPort = 35350;

simnet.minRelay = 1000;

simnet.feeRate = 20000;

simnet.maxFeeRate = 60000;

simnet.identityKey = Buffer.from(
  '104932181cfed7584105c728cdc0eb9af1e7ffdc4a00743fd45e5de66cac7668',
  'hex'
);

simnet.selfConnect = true;

simnet.requestMempool = false;

simnet.claimPrefix = 'hns-simnet:';

simnet.deflationHeight = 0;

/*
 * Expose
 */

network.main = main;
network.testnet = testnet;
network.regtest = regtest;
network.simnet = simnet;
}],
[/* 47 */ 'hsd', '/lib/protocol/genesis.js', function(exports, module, __filename, __dirname, __meta) {
// Autogenerated, do not edit.

'use strict';

const data = __node_require__(48 /* './genesis-data.json' */);
const genesis = exports;

/*
 * Main
 */

genesis.main = {
  version: 0,
  hash: Buffer.from(
    '5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0',
    'hex'),
  prevBlock: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  merkleRoot: Buffer.from(
    '8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15',
    'hex'),
  witnessRoot: Buffer.from(
    '1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351',
    'hex'),
  treeRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  reservedRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  time: 1580745078,
  bits: 0x1c00ffff,
  nonce: 0x00000000,
  extraNonce: Buffer.from(
    '000000000000000000000000000000000000000000000000',
    'hex'),
  mask: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  height: 0,
  magic: 1533997779
};

genesis.mainData = Buffer.from(data.main, 'base64');

/*
 * Testnet
 */

genesis.testnet = {
  version: 0,
  hash: Buffer.from(
    'b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901',
    'hex'),
  prevBlock: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  merkleRoot: Buffer.from(
    '8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15',
    'hex'),
  witnessRoot: Buffer.from(
    '1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351',
    'hex'),
  treeRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  reservedRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  time: 1580745079,
  bits: 0x1d00ffff,
  nonce: 0x00000000,
  extraNonce: Buffer.from(
    '000000000000000000000000000000000000000000000000',
    'hex'),
  mask: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  height: 0,
  magic: 2974944722
};

genesis.testnetData = Buffer.from(data.testnet, 'base64');

/*
 * Regtest
 */

genesis.regtest = {
  version: 0,
  hash: Buffer.from(
    'ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5',
    'hex'),
  prevBlock: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  merkleRoot: Buffer.from(
    '8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15',
    'hex'),
  witnessRoot: Buffer.from(
    '1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351',
    'hex'),
  treeRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  reservedRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  time: 1580745080,
  bits: 0x207fffff,
  nonce: 0x00000000,
  extraNonce: Buffer.from(
    '000000000000000000000000000000000000000000000000',
    'hex'),
  mask: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  height: 0,
  magic: 2922943951
};

genesis.regtestData = Buffer.from(data.regtest, 'base64');

/*
 * Simnet
 */

genesis.simnet = {
  version: 0,
  hash: Buffer.from(
    '0e648edc9cddb179014658061ea3f666a45cf44881877ae506e6babefbef6992',
    'hex'),
  prevBlock: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  merkleRoot: Buffer.from(
    '8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15',
    'hex'),
  witnessRoot: Buffer.from(
    '1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351',
    'hex'),
  treeRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  reservedRoot: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  time: 1580745081,
  bits: 0x207fffff,
  nonce: 0x00000000,
  extraNonce: Buffer.from(
    '000000000000000000000000000000000000000000000000',
    'hex'),
  mask: Buffer.from(
    '0000000000000000000000000000000000000000000000000000000000000000',
    'hex'),
  height: 0,
  magic: 241471196
};

genesis.simnetData = Buffer.from(data.simnet, 'base64');
}],
[/* 48 */ 'hsd', '/lib/protocol/genesis-data.json', function(exports, module, __filename, __dirname, __meta) {
module.exports = {
  "main": "AAAAAHZBOF4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGixguUOSBpOPjXgjeCq9uLIRpXQx6cm2pjZdjUKJM1GOTJdW/vKtEDdfNg4FYPzHWH61Ij3fjNfH4G5goRQLFQAAAAD//wAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////AdBMV3cAAAAAABTwI3ri6Phg99eRJPxRPwEuWqqNIwAAAAAAAAQgULiTf8Xe8I+fPL2n5fCMcG7bgKuliAwAAAAAAAAAAAAgLV3lhgnUlw+1SPha0HqH20DgVONMyByVHKmVpY9nTbcgENdI7aG5xnuU0yROAhFndhiptLMp6JatkEMfn0gDS60g4sApmh5GZ3NRZlXwmmSx4WsleVMN5sSlnOVlTepFGA8=",
  "testnet": "AAAAAHdBOF4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGixguUOSBpOPjXgjeCq9uLIRpXQx6cm2pjZdjUKJM1GOTJdW/vKtEDdfNg4FYPzHWH61Ij3fjNfH4G5goRQLFQAAAAD//wAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////AdBMV3cAAAAAABTwI3ri6Phg99eRJPxRPwEuWqqNIwAAAAAAAAQgULiTf8Xe8I+fPL2n5fCMcG7bgKuliAwAAAAAAAAAAAAgLV3lhgnUlw+1SPha0HqH20DgVONMyByVHKmVpY9nTbcgENdI7aG5xnuU0yROAhFndhiptLMp6JatkEMfn0gDS60g4sApmh5GZ3NRZlXwmmSx4WsleVMN5sSlnOVlTepFGA8=",
  "regtest": "AAAAAHhBOF4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGixguUOSBpOPjXgjeCq9uLIRpXQx6cm2pjZdjUKJM1GOTJdW/vKtEDdfNg4FYPzHWH61Ij3fjNfH4G5goRQLFQAAAAD//38gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////AdBMV3cAAAAAABTwI3ri6Phg99eRJPxRPwEuWqqNIwAAAAAAAAQgULiTf8Xe8I+fPL2n5fCMcG7bgKuliAwAAAAAAAAAAAAgLV3lhgnUlw+1SPha0HqH20DgVONMyByVHKmVpY9nTbcgENdI7aG5xnuU0yROAhFndhiptLMp6JatkEMfn0gDS60g4sApmh5GZ3NRZlXwmmSx4WsleVMN5sSlnOVlTepFGA8=",
  "simnet": "AAAAAHlBOF4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGixguUOSBpOPjXgjeCq9uLIRpXQx6cm2pjZdjUKJM1GOTJdW/vKtEDdfNg4FYPzHWH61Ij3fjNfH4G5goRQLFQAAAAD//38gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////AdBMV3cAAAAAABTwI3ri6Phg99eRJPxRPwEuWqqNIwAAAAAAAAQgULiTf8Xe8I+fPL2n5fCMcG7bgKuliAwAAAAAAAAAAAAgLV3lhgnUlw+1SPha0HqH20DgVONMyByVHKmVpY9nTbcgENdI7aG5xnuU0yROAhFndhiptLMp6JatkEMfn0gDS60g4sApmh5GZ3NRZlXwmmSx4WsleVMN5sSlnOVlTepFGA8="
};
}],
[/* 49 */ 'hsd', '/lib/protocol/timedata.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * timedata.js - time management for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const EventEmitter = require('events');
const util = __node_require__(50 /* '../utils/util' */);
const binary = __node_require__(45 /* '../utils/binary' */);

/**
 * Time Data
 * An object which handles "adjusted time". This may not
 * look it, but this is actually a semi-consensus-critical
 * piece of code. It handles version packets from peers
 * and calculates what to offset our system clock's time by.
 * @alias module:protocol.TimeData
 * @extends EventEmitter
 * @property {Array} samples
 * @property {Object} known
 * @property {Number} limit
 * @property {Number} offset
 */

class TimeData extends EventEmitter {
  /**
   * Create time data.
   * @constructor
   * @param {Number} [limit=200]
   */

  constructor(limit) {
    super();

    if (limit == null)
      limit = 200;

    this.samples = [];
    this.known = new Map();
    this.limit = limit;
    this.offset = 0;
    this.checked = false;
  }

  /**
   * Add time data.
   * @param {String} id
   * @param {Number} time
   */

  add(id, time) {
    if (this.samples.length >= this.limit)
      return;

    if (this.known.has(id))
      return;

    const sample = time - util.now();

    this.known.set(id, sample);

    binary.insert(this.samples, sample, compare);

    this.emit('sample', sample, this.samples.length);

    if (this.samples.length >= 5 && this.samples.length % 2 === 1) {
      let median = this.samples[this.samples.length >>> 1];

      if (Math.abs(median) >= 70 * 60) {
        if (!this.checked) {
          let match = false;

          for (const offset of this.samples) {
            if (offset !== 0 && Math.abs(offset) < 5 * 60) {
              match = true;
              break;
            }
          }

          if (!match) {
            this.checked = true;
            this.emit('mismatch');
          }
        }

        median = 0;
      }

      this.offset = median;
      this.emit('offset', this.offset);
    }
  }

  /**
   * Get the current adjusted time.
   * @returns {Number} Adjusted Time.
   */

  now() {
    return util.now() + this.offset;
  }

  /**
   * Adjust a timestamp.
   * @param {Number} time
   * @returns {Number} Adjusted Time.
   */

  adjust(time) {
    return time + this.offset;
  }

  /**
   * Unadjust a timestamp.
   * @param {Number} time
   * @returns {Number} Local Time.
   */

  local(time) {
    return time - this.offset;
  }

  /**
   * Get the current adjusted time in milliseconds.
   * @returns {Number} Adjusted Time.
   */

  ms() {
    return Date.now() + this.offset * 1000;
  }
}

/*
 * Helpers
 */

function compare(a, b) {
  return a - b;
}

/*
 * Expose
 */

module.exports = TimeData;
}],
[/* 50 */ 'hsd', '/lib/utils/util.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * util.js - utils for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = __node_require__(2 /* 'bsert' */);

/**
 * @exports utils/util
 */

const util = exports;

/**
 * Return hrtime (shim for browser).
 * @param {Array} time
 * @returns {Array} [seconds, nanoseconds]
 */

util.bench = function bench(time) {
  if (!process.hrtime) {
    const now = Date.now();

    if (time) {
      const [hi, lo] = time;
      const start = hi * 1000 + lo / 1e6;
      return now - start;
    }

    const ms = now % 1000;

    // Seconds
    const hi = (now - ms) / 1000;

    // Nanoseconds
    const lo = ms * 1e6;

    return [hi, lo];
  }

  if (time) {
    const [hi, lo] = process.hrtime(time);
    return hi * 1000 + lo / 1e6;
  }

  return process.hrtime();
};

/**
 * Get current time in unix time (seconds).
 * @returns {Number}
 */

util.now = function now() {
  return Math.floor(Date.now() / 1000);
};

/**
 * Get current time in unix time (milliseconds).
 * @returns {Number}
 */

util.ms = function ms() {
  return Date.now();
};

/**
 * Create a Date ISO string from time in unix time (seconds).
 * @param {Number?} time - Seconds in unix time.
 * @returns {String}
 */

util.date = function date(time) {
  if (time == null)
    time = util.now();

  return new Date(time * 1000).toISOString().slice(0, -5) + 'Z';
};

/**
 * Get unix seconds from a Date string.
 * @param {String?} date - Date ISO String.
 * @returns {Number}
 */

util.time = function time(date) {
  if (date == null)
    return util.now();

  return new Date(date) / 1000 | 0;
};

/**
 * Convert u32 to padded hex.
 * @param {Number} num
 * @returns {String}
 */

util.hex32 = function hex32(num) {
  assert((num >>> 0) === num);
  num = num.toString(16);
  switch (num.length) {
    case 1:
      return `0000000${num}`;
    case 2:
      return `000000${num}`;
    case 3:
      return `00000${num}`;
    case 4:
      return `0000${num}`;
    case 5:
      return `000${num}`;
    case 6:
      return `00${num}`;
    case 7:
      return `0${num}`;
    case 8:
      return `${num}`;
    default:
      throw new Error();
  }
};

/**
 * Parse hex.
 * @param {String} str
 * @param {Number} size
 * @returns {Buffer}
 */

util.parseHex = function parseHex(str, size) {
  if (size == null)
    size = -1;

  assert(typeof str === 'string');
  assert(size === -1 || (size >>> 0) === size);

  if (str.length & 1)
    throw new Error('Invalid hex string.');

  if (size !== -1) {
    if ((str.length >>> 1) !== size)
      throw new Error('Invalid hex string.');
  }

  const data = Buffer.from(str, 'hex');

  if (data.length !== (str.length >>> 1))
    throw new Error('Invalid hex string.');

  return data;
};

/**
 * Test whether a number is a safe uint64.
 * @param {Number} num
 * @returns {Boolean}
 */

util.isU64 = function isU64(num) {
  return Number.isSafeInteger(num) && num >= 0;
};

/**
 * Encode a uint32.
 * @param {Number} num
 * @returns {Buffer}
 */

util.encodeU32 = function encodeU32(num) {
  assert(Number.isSafeInteger(num));
  const buf = Buffer.allocUnsafe(4);
  buf[0] = num;
  num >>>= 8;
  buf[1] = num;
  num >>>= 8;
  buf[2] = num;
  num >>>= 8;
  buf[3] = num;
  return buf;
};
}],
[/* 51 */ 'hsd', '/lib/protocol/consensus.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * consensus.js - consensus constants and helpers for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

/**
 * @module protocol/consensus
 */

const assert = __node_require__(2 /* 'bsert' */);
const BN = __node_require__(31 /* 'bcrypto/lib/bn.js' */);

/**
 * Coin exponent.
 * @const {Number}
 * @default
 */

exports.EXP = 6;

/**
 * One handshake in dollarydoos.
 * @const {Amount}
 * @default
 */

exports.COIN = Math.pow(10, exports.EXP);

/**
 * Maximum creators amount in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_CREATORS = 102e6 * exports.COIN;

/**
 * Maximum sponsors amount in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_SPONSORS = 102e6 * exports.COIN;

/**
 * Maximum TLD holder amount in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_TLD = 51e6 * exports.COIN;

/**
 * Maximum domain holder amount in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_DOMAIN = 51e6 * exports.COIN;

/**
 * Maximum CA/naming amount in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_CA_NAMING = 102e6 * exports.COIN;

/**
 * Maximum airdrop amount in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_AIRDROP = 0.952e9 * exports.COIN;

/**
 * Maximum initial supply in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_INITIAL = 1.36e9 * exports.COIN;

assert(exports.MAX_CREATORS
     + exports.MAX_SPONSORS
     + exports.MAX_TLD
     + exports.MAX_DOMAIN
     + exports.MAX_CA_NAMING
     + exports.MAX_AIRDROP === exports.MAX_INITIAL);

/**
 * Maximum amount of subsidies in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_SUBSIDY = 0.68e9 * exports.COIN;

assert(exports.MAX_INITIAL / 2 === exports.MAX_SUBSIDY);

/**
 * Maximum amount of money in dollarydoos (consensus).
 * @const {Amount}
 * @default
 */

exports.MAX_MONEY = 2.04e9 * exports.COIN;

assert(exports.MAX_INITIAL + exports.MAX_SUBSIDY === exports.MAX_MONEY);

/**
 * Base block subsidy (consensus).
 * @const {Amount}
 * @default
 */

exports.BASE_REWARD = 2000 * exports.COIN;

assert(2 * exports.BASE_REWARD * 170000 === exports.MAX_SUBSIDY);

/**
 * Block subsidy specifically for the genesis block.
 *
 * Explanation:
 * The max miner subsidy is 680000000, but due
 * to the halving interval it actually ends up
 * as 679999995.79, so add 2.21 coins to the
 * genesis reward output to make MAX_MONEY a
 * thoroughly true value.
 *
 * This, combined with the 3 1/4 year halving
 * interval, causes the supply to run dry
 * after about 100 years (around the year 2119,
 * or height=5,270,000).
 *
 * @const {Amount}
 * @default
 */

exports.GENESIS_REWARD = exports.BASE_REWARD + ((2.21 * exports.COIN) | 0);

/**
 * Genesis key.
 * @const {Buffer}
 */

exports.GENESIS_KEY =
  Buffer.from('f0237ae2e8f860f7d79124fc513f012e5aaa8d23', 'hex');

/**
 * Maximum block base size (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_SIZE = 1000000;

/**
 * Maximum block serialization size (protocol).
 * @const {Number}
 * @default
 */

exports.MAX_RAW_BLOCK_SIZE = 4000000;

/**
 * Maximum block weight (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_WEIGHT = 4000000;

/**
 * Maximum block sigops cost (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_SIGOPS = 80000;

/**
 * Maximum block tree opens.
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_OPENS = 300;

/**
 * Maximum block tree updates.
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_UPDATES = 600;

/**
 * Maximum block tree renewals.
 * @const {Number}
 * @default
 */

exports.MAX_BLOCK_RENEWALS = 600;

/**
 * Size of set to pick median time from.
 * @const {Number}
 * @default
 */

exports.MEDIAN_TIMESPAN = 11;

/**
 * Amount to multiply base/non-witness sizes by.
 * @const {Number}
 * @default
 */

exports.WITNESS_SCALE_FACTOR = 4;

/**
 * Maximum TX base size (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_TX_SIZE = 1000000;

/**
 * Maximum TX weight (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_TX_WEIGHT = 4000000;

/**
 * Locktime flag.
 * @const {Number}
 * @default
 */

exports.LOCKTIME_FLAG = (1 << 31) >>> 0;

/**
 * Locktime mask.
 * @const {Number}
 * @default
 */

exports.LOCKTIME_MASK = exports.LOCKTIME_FLAG - 1;

/**
 * Locktime granularity.
 * @const {Number}
 * @default
 */

exports.LOCKTIME_GRANULARITY = 9;

/**
 * Locktime multiplier.
 * @const {Number}
 * @default
 */

exports.LOCKTIME_MULT = 2 ** exports.LOCKTIME_GRANULARITY;

/**
 * Highest nSequence bit -- disables
 * sequence locktimes (consensus).
 * @const {Number}
 */

exports.SEQUENCE_DISABLE_FLAG = (1 << 31) >>> 0;

/**
 * Sequence time: height or time (consensus).
 * @const {Number}
 * @default
 */

exports.SEQUENCE_TYPE_FLAG = 1 << 22;

/**
 * Sequence granularity for time (consensus).
 * @const {Number}
 * @default
 */

exports.SEQUENCE_GRANULARITY = 9;

/**
 * Sequence mask (consensus).
 * @const {Number}
 * @default
 */

exports.SEQUENCE_MASK = 0x0000ffff;

/**
 * Max serialized script size (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_SCRIPT_SIZE = 10000;

/**
 * Max stack size during execution (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_SCRIPT_STACK = 1000;

/**
 * Max script element size (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_SCRIPT_PUSH = 520;

/**
 * Max opcodes executed (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_SCRIPT_OPS = 201;

/**
 * Max `n` value for multisig (consensus).
 * @const {Number}
 * @default
 */

exports.MAX_MULTISIG_PUBKEYS = 20;

/**
 * A hash of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_HASH = Buffer.alloc(32, 0x00);

/**
 * Block header size.
 * @const {Number}
 * @default
 */

exports.HEADER_SIZE = 236;

/**
 * Block header nonce size.
 * @const {Number}
 * @default
 */

exports.NONCE_SIZE = 24;

/**
 * Block header of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_HEADER = Buffer.alloc(exports.HEADER_SIZE, 0x00);

/**
 * Block header nonce of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_NONCE = Buffer.alloc(exports.NONCE_SIZE, 0x00);

/**
 * Convert a compact number to a big number.
 * Used for `block.bits` -> `target` conversion.
 * @param {Number} compact
 * @returns {BN}
 */

exports.fromCompact = function fromCompact(compact) {
  if (compact === 0)
    return new BN(0);

  const exponent = compact >>> 24;
  const negative = (compact >>> 23) & 1;

  let mantissa = compact & 0x7fffff;
  let num;

  if (exponent <= 3) {
    mantissa >>>= 8 * (3 - exponent);
    num = new BN(mantissa);
  } else {
    num = new BN(mantissa);
    num.iushln(8 * (exponent - 3));
  }

  if (negative)
    num.ineg();

  return num;
};

/**
 * Convert a big number to a compact number.
 * Used for `target` -> `block.bits` conversion.
 * @param {BN} num
 * @returns {Number}
 */

exports.toCompact = function toCompact(num) {
  if (num.isZero())
    return 0;

  let exponent = num.byteLength();
  let mantissa;

  if (exponent <= 3) {
    mantissa = num.toNumber();
    mantissa <<= 8 * (3 - exponent);
  } else {
    mantissa = num.ushrn(8 * (exponent - 3)).toNumber();
  }

  if (mantissa & 0x800000) {
    mantissa >>>= 8;
    exponent += 1;
  }

  let compact = (exponent << 24) | mantissa;

  if (num.isNeg())
    compact |= 0x800000;

  compact >>>= 0;

  return compact;
};

/**
 * Verify proof-of-work.
 * @param {Hash} hash
 * @param {Number} bits
 * @returns {Boolean}
 */

exports.verifyPOW = function verifyPOW(hash, bits) {
  const target = exports.fromCompact(bits);

  if (target.isNeg() || target.isZero())
    return false;

  if (target.bitLength() > 256)
    return false;

  const num = new BN(hash, 'be');

  if (num.gt(target))
    return false;

  return true;
};

/**
 * Calculate block subsidy.
 * @param {Number} height - Reward era by height.
 * @returns {Amount}
 */

exports.getReward = function getReward(height, interval) {
  assert((height >>> 0) === height, 'Bad height for reward.');
  assert((interval >>> 0) === interval);

  const halvings = Math.floor(height / interval);

  if (halvings >= 52)
    return 0;

  return Math.floor(exports.BASE_REWARD / Math.pow(2, halvings));
};

/**
 * Test version bit.
 * @param {Number} version
 * @param {Number} bit
 * @returns {Boolean}
 */

exports.hasBit = function hasBit(version, bit) {
  return (version & (1 << bit)) !== 0;
};
}],
[/* 52 */ 'hsd', '/lib/hd/common.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * common.js - common functions for hd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = __node_require__(2 /* 'bsert' */);
const LRU = __node_require__(53 /* 'blru' */);
const common = exports;

/**
 * Index at which hardening begins.
 * @const {Number}
 * @default
 */

common.HARDENED = 0x80000000;

/**
 * Min entropy bits.
 * @const {Number}
 * @default
 */

common.MIN_ENTROPY = 128;

/**
 * Max entropy bits.
 * @const {Number}
 * @default
 */

common.MAX_ENTROPY = 512;

/**
 * LRU cache to avoid deriving keys twice.
 * @type {LRU}
 */

common.cache = new LRU(500);

/**
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @param {String} path
 * @param {Boolean} hard
 * @returns {Number[]}
 */

common.parsePath = function parsePath(path, hard) {
  assert(typeof path === 'string');
  assert(typeof hard === 'boolean');
  assert(path.length >= 1);
  assert(path.length <= 3062);

  const parts = path.split('/');
  const root = parts[0];

  if (root !== 'm'
      && root !== 'M'
      && root !== 'm\''
      && root !== 'M\'') {
    throw new Error('Invalid path root.');
  }

  const result = [];

  for (let i = 1; i < parts.length; i++) {
    let part = parts[i];

    const hardened = part[part.length - 1] === '\'';

    if (hardened)
      part = part.slice(0, -1);

    if (part.length > 10)
      throw new Error('Path index too large.');

    if (!/^\d+$/.test(part))
      throw new Error('Path index is non-numeric.');

    let index = parseInt(part, 10);

    if ((index >>> 0) !== index)
      throw new Error('Path index out of range.');

    if (hardened) {
      index |= common.HARDENED;
      index >>>= 0;
    }

    if (!hard && (index & common.HARDENED))
      throw new Error('Path index cannot be hardened.');

    result.push(index);
  }

  return result;
};

/**
 * Test whether the key is a master key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @returns {Boolean}
 */

common.isMaster = function isMaster(key) {
  return key.depth === 0
    && key.childIndex === 0
    && key.parentFingerPrint === 0;
};

/**
 * Test whether the key is (most likely) a BIP44 account key.
 * @param {HDPrivateKey|HDPublicKey} key
 * @param {Number?} account
 * @returns {Boolean}
 */

common.isAccount = function isAccount(key, account) {
  if (account != null) {
    const index = (common.HARDENED | account) >>> 0;
    if (key.childIndex !== index)
      return false;
  }
  return key.depth === 3 && (key.childIndex & common.HARDENED) !== 0;
};

/**
 * A compressed pubkey of all zeroes.
 * @const {Buffer}
 * @default
 */

common.ZERO_KEY = Buffer.alloc(33, 0x00);
}],
[/* 53 */ 'blru', '/lib/blru.js', function(exports, module, __filename, __dirname, __meta) {
'use strict';

module.exports = __node_require__(54 /* './lru' */);
}],
[/* 54 */ 'blru', '/lib/lru.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * lru.js - LRU cache for bcoin
 * Copyright (c) 2014-2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = __node_require__(2 /* 'bsert' */);

/**
 * LRU Cache
 */

class LRU {
  /**
   * Create an LRU cache.
   * @constructor
   * @param {Number} capacity
   * @param {Function?} getSize
   * @param {Function?} CustomMap
   */

  constructor(capacity, getSize, CustomMap) {
    assert(typeof capacity === 'number', 'Capacity must be a number.');
    assert(capacity >= 0, 'Capacity cannot be negative.');
    assert(!getSize || typeof getSize === 'function', 'Bad size callback.');
    assert(!CustomMap || typeof CustomMap === 'function');

    this.map = CustomMap ? new CustomMap() : new Map();
    this.size = 0;
    this.items = 0;
    this.head = null;
    this.tail = null;
    this.pending = null;

    this.capacity = capacity;
    this.getSize = getSize;
  }

  /**
   * Calculate size of an item.
   * @private
   * @param {LRUItem} item
   * @returns {Number} Size.
   */

  _getSize(item) {
    if (this.getSize)
      return 120 + this.getSize(item.value, item.key);

    return 1;
  }

  /**
   * Compact the LRU linked list.
   * @private
   */

  _compact() {
    if (this.size <= this.capacity)
      return;

    let item = null;
    let next = null;

    for (item = this.head; item; item = next) {
      if (this.size <= this.capacity)
        break;

      this.size -= this._getSize(item);
      this.items -= 1;
      this.map.delete(item.key);

      next = item.next;

      item.prev = null;
      item.next = null;
    }

    if (!item) {
      this.head = null;
      this.tail = null;
      return;
    }

    this.head = item;
    item.prev = null;
  }

  /**
   * Reset the cache. Clear all items.
   */

  reset() {
    let item, next;

    for (item = this.head; item; item = next) {
      this.map.delete(item.key);
      this.items -= 1;
      next = item.next;
      item.prev = null;
      item.next = null;
    }

    assert(!item);

    this.size = 0;
    this.head = null;
    this.tail = null;
  }

  /**
   * Add an item to the cache.
   * @param {String|Number} key
   * @param {Object} value
   */

  set(key, value) {
    if (this.capacity === 0)
      return;

    let item = this.map.get(key);

    if (item) {
      this.size -= this._getSize(item);
      item.value = value;
      this.size += this._getSize(item);
      this._removeList(item);
      this._appendList(item);
      this._compact();
      return;
    }

    item = new LRUItem(key, value);

    this.map.set(key, item);

    this._appendList(item);

    this.size += this._getSize(item);
    this.items += 1;

    this._compact();
  }

  /**
   * Retrieve an item from the cache.
   * @param {String|Number} key
   * @returns {Object} Item.
   */

  get(key) {
    if (this.capacity === 0)
      return null;

    const item = this.map.get(key);

    if (!item)
      return null;

    this._removeList(item);
    this._appendList(item);

    return item.value;
  }

  /**
   * Test whether the cache contains a key.
   * @param {String|Number} key
   * @returns {Boolean}
   */

  has(key) {
    if (this.capacity === 0)
      return false;
    return this.map.has(key);
  }

  /**
   * Remove an item from the cache.
   * @param {String|Number} key
   * @returns {Boolean} Whether an item was removed.
   */

  remove(key) {
    if (this.capacity === 0)
      return false;

    const item = this.map.get(key);

    if (!item)
      return false;

    this.size -= this._getSize(item);
    this.items -= 1;

    this.map.delete(key);

    this._removeList(item);

    return true;
  }

  /**
   * Prepend an item to the linked list (sets new head).
   * @private
   * @param {LRUItem}
   */

  _prependList(item) {
    this._insertList(null, item);
  }

  /**
   * Append an item to the linked list (sets new tail).
   * @private
   * @param {LRUItem}
   */

  _appendList(item) {
    this._insertList(this.tail, item);
  }

  /**
   * Insert item into the linked list.
   * @private
   * @param {LRUItem|null} ref
   * @param {LRUItem} item
   */

  _insertList(ref, item) {
    assert(!item.next);
    assert(!item.prev);

    if (ref == null) {
      if (!this.head) {
        this.head = item;
        this.tail = item;
      } else {
        this.head.prev = item;
        item.next = this.head;
        this.head = item;
      }
      return;
    }

    item.next = ref.next;
    item.prev = ref;
    ref.next = item;

    if (item.next)
      item.next.prev = item;

    if (ref === this.tail)
      this.tail = item;
  }

  /**
   * Remove item from the linked list.
   * @private
   * @param {LRUItem}
   */

  _removeList(item) {
    if (item.prev)
      item.prev.next = item.next;

    if (item.next)
      item.next.prev = item.prev;

    if (item === this.head)
      this.head = item.next;

    if (item === this.tail)
      this.tail = item.prev || this.head;

    if (!this.head)
      assert(!this.tail);

    if (!this.tail)
      assert(!this.head);

    item.prev = null;
    item.next = null;
  }

  /**
   * Collect all keys in the cache, sorted by LRU.
   * @returns {String[]}
   */

  keys() {
    const items = [];

    for (let item = this.head; item; item = item.next) {
      if (item === this.head)
        assert(!item.prev);
      if (!item.prev)
        assert(item === this.head);
      if (!item.next)
        assert(item === this.tail);
      items.push(item.key);
    }

    return items;
  }

  /**
   * Collect all values in the cache, sorted by LRU.
   * @returns {String[]}
   */

  values() {
    const items = [];

    for (let item = this.head; item; item = item.next)
      items.push(item.value);

    return items;
  }

  /**
   * Convert the LRU cache to an array of items.
   * @returns {Object[]}
   */

  toArray() {
    const items = [];

    for (let item = this.head; item; item = item.next)
      items.push(item);

    return items;
  }

  /**
   * Create an atomic batch for the lru
   * (used for caching database writes).
   * @returns {LRUBatch}
   */

  batch() {
    return new LRUBatch(this);
  }

  /**
   * Start the pending batch.
   */

  start() {
    assert(!this.pending);
    this.pending = this.batch();
  }

  /**
   * Clear the pending batch.
   */

  clear() {
    assert(this.pending);
    this.pending.clear();
  }

  /**
   * Drop the pending batch.
   */

  drop() {
    assert(this.pending);
    this.pending = null;
  }

  /**
   * Commit the pending batch.
   */

  commit() {
    assert(this.pending);
    this.pending.commit();
    this.pending = null;
  }

  /**
   * Push an item onto the pending batch.
   * @param {String} key
   * @param {Object} value
   */

  push(key, value) {
    assert(this.pending);

    if (this.capacity === 0)
      return;

    this.pending.set(key, value);
  }

  /**
   * Push a removal onto the pending batch.
   * @param {String} key
   */

  unpush(key) {
    assert(this.pending);

    if (this.capacity === 0)
      return;

    this.pending.remove(key);
  }
}

/**
 * LRU Item
 * @alias module:utils.LRUItem
 */

class LRUItem {
  /**
   * Create an LRU item.
   * @constructor
   * @private
   * @param {String} key
   * @param {Object} value
   */

  constructor(key, value) {
    this.key = key;
    this.value = value;
    this.next = null;
    this.prev = null;
  }
}

/**
 * LRU Batch
 * @alias module:utils.LRUBatch
 */

class LRUBatch {
  /**
   * Create an LRU batch.
   * @constructor
   * @param {LRU} lru
   */

  constructor(lru) {
    this.lru = lru;
    this.ops = [];
  }

  /**
   * Push an item onto the batch.
   * @param {String} key
   * @param {Object} value
   */

  set(key, value) {
    this.ops.push(new LRUOp(false, key, value));
  }

  /**
   * Push a removal onto the batch.
   * @param {String} key
   */

  remove(key) {
    this.ops.push(new LRUOp(true, key, null));
  }

  /**
   * Clear the batch.
   */

  clear() {
    this.ops.length = 0;
  }

  /**
   * Commit the batch.
   */

  commit() {
    for (const op of this.ops) {
      if (op.remove) {
        this.lru.remove(op.key);
        continue;
      }
      this.lru.set(op.key, op.value);
    }

    this.ops.length = 0;
  }
}

/**
 * LRU Op
 * @alias module:utils.LRUOp
 * @private
 */

class LRUOp {
  /**
   * Create an LRU op.
   * @constructor
   * @param {Boolean} remove
   * @param {String} key
   * @param {Object} value
   */

  constructor(remove, key, value) {
    this.remove = remove;
    this.key = key;
    this.value = value;
  }
}

/*
 * Expose
 */

module.exports = LRU;
}],
[/* 55 */ 'hsd', '/lib/primitives/address.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * address.js - address object for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = __node_require__(2 /* 'bsert' */);
const bio = __node_require__(3 /* 'bufio' */);
const bech32 = __node_require__(56 /* 'bcrypto/lib/encoding/bech32' */);
const blake2b = __node_require__(58 /* 'bcrypto/lib/blake2b' */);
const sha3 = __node_require__(60 /* 'bcrypto/lib/sha3' */);
const Network = __node_require__(44 /* '../protocol/network' */);
const consensus = __node_require__(51 /* '../protocol/consensus' */);

/*
 * Constants
 */

const ZERO_HASH160 = Buffer.alloc(20, 0x00);

/**
 * Address
 * Represents an address.
 * @alias module:primitives.Address
 * @property {Number} version
 * @property {Buffer} hash
 */

class Address extends bio.Struct {
  /**
   * Create an address.
   * @constructor
   * @param {Object?} options
   */

  constructor(options, network) {
    super();

    this.version = 0;
    this.hash = ZERO_HASH160;

    if (options)
      this.fromOptions(options, network);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options, network) {
    if (typeof options === 'string')
      return this.fromString(options, network);

    assert(options);

    const {hash, version} = options;

    return this.fromHash(hash, version);
  }

  /**
   * Count the sigops in a script, taking into account witness programs.
   * @param {Witness} witness
   * @returns {Number} sigop count
   */

  getSigops(witness) {
    if (this.version === 0) {
      if (this.hash.length === 20)
        return 1;

      if (this.hash.length === 32 && witness.items.length > 0) {
        const redeem = witness.getRedeem();
        return redeem.getSigops();
      }
    }

    return 0;
  }

  /**
   * Get the address hash.
   * @returns {Hash}
   */

  getHash() {
    return this.hash;
  }

  /**
   * Test whether the address is null.
   * @returns {Boolean}
   */

  isNull() {
    if (this.hash.length === 20)
      return this.hash.equals(ZERO_HASH160);

    if (this.hash.length === 32)
      return this.hash.equals(consensus.ZERO_HASH);

    for (let i = 0; i < this.hash.length; i++) {
      if (this.hash[i] !== 0)
        return false;
    }

    return true;
  }

  /**
   * Test whether the address is unspendable.
   * @returns {Boolean}
   */

  isUnspendable() {
    return this.isNulldata();
  }

  /**
   * Test equality against another address.
   * @param {Address} addr
   * @returns {Boolean}
   */

  equals(addr) {
    assert(addr instanceof Address);

    return this.version === addr.version
      && this.hash.equals(addr.hash);
  }

  /**
   * Compare against another address.
   * @param {Address} addr
   * @returns {Boolean}
   */

  compare(addr) {
    assert(addr instanceof Address);

    const cmp = this.version - addr.version;

    if (cmp !== 0)
      return cmp;

    return this.hash.compare(addr.hash);
  }

  /**
   * Inject properties from another address.
   * @param {Address} addr
   * @returns {Boolean}
   */

  inject(addr) {
    this.version = addr.version;
    this.hash = addr.hash;
    return this;
  }

  /**
   * Clone address.
   * @returns {Address}
   */

  clone() {
    return new this.constructor().inject(this);
  }

  /**
   * Compile the address object to a bech32 address.
   * @param {{NetworkType|Network)?} network
   * @returns {String}
   * @throws Error on bad hash/prefix.
   */

  toString(network) {
    const version = this.version;
    const hash = this.hash;

    assert(version <= 31);
    assert(hash.length >= 2 && hash.length <= 40);

    network = Network.get(network);

    const hrp = network.addressPrefix;

    return bech32.encode(hrp, version, hash);
  }

  /**
   * Instantiate address from pubkey.
   * @param {Buffer} key
   * @returns {Address}
   */

  fromPubkey(key) {
    assert(Buffer.isBuffer(key) && key.length === 33);
    return this.fromHash(blake2b.digest(key, 20), 0);
  }

  /**
   * Instantiate address from script.
   * @param {Script} script
   * @returns {Address}
   */

  fromScript(script) {
    assert(script && typeof script.encode === 'function');
    return this.fromHash(sha3.digest(script.encode()), 0);
  }

  /**
   * Inject properties from bech32 address.
   * @private
   * @param {String} data
   * @param {Network?} network
   * @throws Parse error
   */

  fromString(data, network) {
    assert(typeof data === 'string');

    const [hrp, version, hash] = bech32.decode(data);

    Network.fromAddress(hrp, network);

    return this.fromHash(hash, version);
  }

  /**
   * Inject properties from witness.
   * @private
   * @param {Witness} witness
   */

  fromWitness(witness) {
    const [, pk] = witness.getPubkeyhashInput();

    if (pk) {
      this.hash = blake2b.digest(pk, 20);
      this.version = 0;
      return this;
    }

    const redeem = witness.getScripthashInput();

    if (redeem) {
      this.hash = sha3.digest(redeem);
      this.version = 0;
      return this;
    }

    return null;
  }

  /**
   * Inject properties from a hash.
   * @private
   * @param {Buffer|Hash} hash
   * @param {Number} [version=-1]
   * @throws on bad hash size
   */

  fromHash(hash, version) {
    if (version == null)
      version = 0;

    assert(Buffer.isBuffer(hash));
    assert((version & 0xff) === version);

    assert(version >= 0 && version <= 31, 'Bad program version.');
    assert(hash.length >= 2 && hash.length <= 40, 'Hash is the wrong size.');

    if (version === 0) {
      assert(hash.length === 20 || hash.length === 32,
        'Witness program hash is the wrong size.');
    }

    this.hash = hash;
    this.version = version;

    return this;
  }

  /**
   * Inject properties from witness pubkeyhash.
   * @private
   * @param {Buffer} hash
   * @returns {Address}
   */

  fromPubkeyhash(hash) {
    assert(hash && hash.length === 20, 'P2WPKH must be 20 bytes.');
    return this.fromHash(hash, 0);
  }

  /**
   * Inject properties from witness scripthash.
   * @private
   * @param {Buffer} hash
   * @returns {Address}
   */

  fromScripthash(hash) {
    assert(hash && hash.length === 32, 'P2WSH must be 32 bytes.');
    return this.fromHash(hash, 0);
  }

  /**
   * Inject properties from witness program.
   * @private
   * @param {Number} version
   * @param {Buffer} hash
   * @returns {Address}
   */

  fromProgram(version, hash) {
    assert(version >= 0, 'Bad version for witness program.');
    return this.fromHash(hash, version);
  }

  /**
   * Instantiate address from nulldata.
   * @param {Buffer} data
   * @returns {Address}
   */

  fromNulldata(data) {
    return this.fromHash(data, 31);
  }

  /**
   * Test whether the address is witness pubkeyhash.
   * @returns {Boolean}
   */

  isPubkeyhash() {
    return this.version === 0 && this.hash.length === 20;
  }

  /**
   * Test whether the address is witness scripthash.
   * @returns {Boolean}
   */

  isScripthash() {
    return this.version === 0 && this.hash.length === 32;
  }

  /**
   * Test whether the address is unspendable.
   * @returns {Boolean}
   */

  isNulldata() {
    return this.version === 31;
  }

  /**
   * Test whether the address is an unknown witness program.
   * @returns {Boolean}
   */

  isUnknown() {
    switch (this.version) {
      case 0:
        return this.hash.length !== 20 && this.hash.length !== 32;
      case 31:
        return false;
    }
    return true;
  }

  /**
   * Test address validity.
   * @returns {Boolean}
   */

  isValid() {
    assert(this.version >= 0);

    if (this.version > 31)
      return false;

    if (this.hash.length < 2 || this.hash.length > 40)
      return false;

    return true;
  }

  /**
   * Calculate address size.
   * @returns {Number}
   */

  getSize() {
    return 1 + 1 + this.hash.length;
  }

  /**
   * Write address to buffer writer.
   * @param {BufferWriter} bw
   * @returns {BufferWriter}
   */

  write(bw) {
    bw.writeU8(this.version);
    bw.writeU8(this.hash.length);
    bw.writeBytes(this.hash);
    return bw;
  }

  /**
   * Read address from buffer reader.
   * @param {BufferReader} br
   * @returns {Address}
   */

  read(br) {
    const version = br.readU8();
    assert(version <= 31);

    const size = br.readU8();
    assert(size >= 2 && size <= 40);

    const hash = br.readBytes(size);

    return this.fromHash(hash, version);
  }

  /**
   * Inspect the Address.
   * @returns {Object}
   */

  format() {
    return '<Address:'
      + ` version=${this.version}`
      + ` str=${this.toString()}`
      + '>';
  }

  /**
   * Instantiate address from pubkey.
   * @param {Buffer} key
   * @returns {Address}
   */

  static fromPubkey(key) {
    return new this().fromPubkey(key);
  }

  /**
   * Instantiate address from script.
   * @param {Script} script
   * @returns {Address}
   */

  static fromScript(script) {
    return new this().fromScript(script);
  }

  /**
   * Create an Address from a witness.
   * Attempt to extract address
   * properties from a witness.
   * @param {Witness}
   * @returns {Address|null}
   */

  static fromWitness(witness) {
    return new this().fromWitness(witness);
  }

  /**
   * Create a naked address from hash/version.
   * @param {Hash} hash
   * @param {Number} [version=-1]
   * @returns {Address}
   * @throws on bad hash size
   */

  static fromHash(hash, version) {
    return new this().fromHash(hash, version);
  }

  /**
   * Instantiate address from witness pubkeyhash.
   * @param {Buffer} hash
   * @returns {Address}
   */

  static fromPubkeyhash(hash) {
    return new this().fromPubkeyhash(hash);
  }

  /**
   * Instantiate address from witness scripthash.
   * @param {Buffer} hash
   * @returns {Address}
   */

  static fromScripthash(hash) {
    return new this().fromScripthash(hash);
  }

  /**
   * Instantiate address from witness program.
   * @param {Number} version
   * @param {Buffer} hash
   * @returns {Address}
   */

  static fromProgram(version, hash) {
    return new this().fromProgram(version, hash);
  }

  /**
   * Instantiate address from nulldata.
   * @param {Buffer} data
   * @returns {Address}
   */

  static fromNulldata(data) {
    return new this().fromNulldata(data);
  }

  /**
   * Get the hash of a base58 address or address-related object.
   * @param {String|Address|Hash} data
   * @param {Network?} network
   * @returns {Hash}
   */

  static getHash(data, network) {
    if (!data)
      throw new Error('Object is not an address.');

    if (Buffer.isBuffer(data)) {
      return data;
    }

    if (data instanceof Address)
      return data.hash;

    throw new Error('Object is not an address.');
  }
}

/*
 * Expose
 */

module.exports = Address;
}],
[/* 56 */ 'bcrypto', '/lib/encoding/bech32-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(57 /* '../js/bech32' */);
}],
[/* 57 */ 'bcrypto', '/lib/js/bech32.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * bech32.js - bech32 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on sipa/bech32:
 *   Copyright (c) 2017, Pieter Wuille (MIT License).
 *   https://github.com/sipa/bech32
 *
 * Resources:
 *   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 *   https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.c
 *   https://github.com/bitcoin/bitcoin/blob/master/src/bech32.cpp
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);

/**
 * Constants
 */

const POOL65 = Buffer.alloc(65);
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  15, -1, 10, 17, 21, 20, 26, 30,
   7,  5, -1, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1,
  -1, 29, -1, 24, 13, 25,  9,  8,
  23, -1, 18, 22, 31, 27, 19, -1,
   1,  0,  3, 16, 11, 28, 12, 14,
   6,  4,  2, -1, -1, -1, -1, -1
];

/**
 * Update checksum.
 * @ignore
 * @param {Number} c
 * @returns {Number}
 */

function polymod(c) {
  const b = c >>> 25;

  return ((c & 0x1ffffff) << 5)
    ^ (0x3b6a57b2 & -((b >> 0) & 1))
    ^ (0x26508e6d & -((b >> 1) & 1))
    ^ (0x1ea119fa & -((b >> 2) & 1))
    ^ (0x3d4233dd & -((b >> 3) & 1))
    ^ (0x2a1462b3 & -((b >> 4) & 1));
}

/**
 * Encode hrp and data as a bech32 string.
 * @param {String} hrp
 * @param {Buffer} data
 * @returns {String}
 */

function serialize(hrp, data) {
  assert(typeof hrp === 'string');
  assert(Buffer.isBuffer(data));

  if (hrp.length === 0 || hrp.length > 83)
    throw new Error('Invalid bech32 human-readable part.');

  if (hrp.length + 1 + data.length + 6 > 90)
    throw new Error('Invalid bech32 data length.');

  let str = '';
  let chk = 1;
  let i;

  for (i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Invalid bech32 character.');

    if (ch >= 65 && ch <= 90)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ (ch >> 5);
  }

  chk = polymod(chk);

  for (let i = 0; i < hrp.length; i++) {
    const ch = hrp.charCodeAt(i);

    chk = polymod(chk) ^ (ch & 0x1f);

    str += hrp[i];
  }

  str += '1';

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    if (ch >> 5)
      throw new Error('Invalid bech32 value.');

    chk = polymod(chk) ^ ch;

    str += CHARSET[ch];
  }

  for (let i = 0; i < 6; i++)
    chk = polymod(chk);

  chk ^= 1;

  for (let i = 0; i < 6; i++)
    str += CHARSET[(chk >>> ((5 - i) * 5)) & 0x1f];

  return str;
}

/**
 * Decode a bech32 string.
 * @param {String} str
 * @returns {Array} [hrp, data]
 */

function deserialize(str) {
  assert(typeof str === 'string');

  if (str.length < 8 || str.length > 90)
    throw new Error('Invalid bech32 string length.');

  let lower = false;
  let upper = false;
  let hlen = 0;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch < 33 || ch > 126)
      throw new Error('Invalid bech32 character.');

    if (ch >= 97 && ch <= 122)
      lower = true;
    else if (ch >= 65 && ch <= 90)
      upper = true;
    else if (ch === 49)
      hlen = i;
  }

  if (hlen === 0)
    throw new Error('Invalid bech32 human-readable part.');

  const dlen = str.length - (hlen + 1);

  if (dlen < 6)
    throw new Error('Invalid bech32 data length.');

  if (lower && upper)
    throw new Error('Invalid bech32 casing.');

  let chk = 1;
  let hrp = '';

  for (let i = 0; i < hlen; i++) {
    let ch = str.charCodeAt(i);

    if (ch >= 65 && ch <= 90)
      ch += 32;

    chk = polymod(chk) ^ (ch >> 5);

    hrp += String.fromCharCode(ch);
  }

  chk = polymod(chk);

  for (let i = 0; i < hlen; i++)
    chk = polymod(chk) ^ (str.charCodeAt(i) & 0x1f);

  const data = Buffer.alloc(dlen - 6);

  let j = 0;

  for (let i = hlen + 1; i < str.length; i++) {
    const val = TABLE[str.charCodeAt(i)];

    if (val === -1)
      throw new Error('Invalid bech32 character.');

    chk = polymod(chk) ^ val;

    if (i < str.length - 6)
      data[j++] = val;
  }

  if (chk !== 1)
    throw new Error('Invalid bech32 checksum.');

  assert(j === data.length);

  return [hrp, data];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} str
 * @returns {Boolean}
 */

function is(str) {
  assert(typeof str === 'string');

  try {
    deserialize(str);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} dst
 * @param {Number} dstoff
 * @param {Number} dstbits
 * @param {Buffer} src
 * @param {Number} srcoff
 * @param {Number} srcbits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convert(dst, dstoff, dstbits, src, srcoff, srcbits, pad) {
  assert(Buffer.isBuffer(dst));
  assert((dstoff >>> 0) === dstoff);
  assert((dstbits >>> 0) === dstbits);
  assert(Buffer.isBuffer(src));
  assert((srcoff >>> 0) === srcoff);
  assert((srcbits >>> 0) === srcbits);
  assert(typeof pad === 'boolean');
  assert(dstbits >= 1 && dstbits <= 8);
  assert(srcbits >= 1 && srcbits <= 8);

  const mask = (1 << dstbits) - 1;

  let acc = 0;
  let bits = 0;
  let i = srcoff;
  let j = dstoff;

  for (; i < src.length; i++) {
    acc = (acc << srcbits) | src[i];
    bits += srcbits;

    while (bits >= dstbits) {
      bits -= dstbits;
      dst[j++] = (acc >>> bits) & mask;
    }
  }

  const left = dstbits - bits;

  if (pad) {
    if (bits)
      dst[j++] = (acc << left) & mask;
  } else {
    if (((acc << left) & mask) || bits >= srcbits)
      throw new Error('Invalid bits.');
  }

  assert(j <= dst.length);

  return dst.slice(0, j);
}

/**
 * Calculate size required for bit conversion.
 * @param {Number} len
 * @param {Number} srcbits
 * @param {Number} dstbits
 * @param {Boolean} pad
 * @returns {Number}
 */

function convertSize(len, srcbits, dstbits, pad) {
  assert((len >>> 0) === len);
  assert((srcbits >>> 0) === srcbits);
  assert((dstbits >>> 0) === dstbits);
  assert(typeof pad === 'boolean');
  assert(srcbits >= 1 && srcbits <= 8);
  assert(dstbits >= 1 && dstbits <= 8);

  return ((len * srcbits + (dstbits - 1) * (pad | 0)) / dstbits) >>> 0;
}

/**
 * Convert serialized data to another base.
 * @param {Buffer} data
 * @param {Number} srcbits
 * @param {Number} dstbits
 * @param {Boolean} pad
 * @returns {Buffer}
 */

function convertBits(data, srcbits, dstbits, pad) {
  assert(Buffer.isBuffer(data));

  const size = convertSize(data.length, srcbits, dstbits, pad);
  const out = Buffer.alloc(size);

  return convert(out, 0, dstbits, data, 0, srcbits, pad);
}

/**
 * Serialize data to bech32 address.
 * @param {String} hrp
 * @param {Number} version
 * @param {Buffer} hash
 * @returns {String}
 */

function encode(hrp, version, hash) {
  assert(typeof hrp === 'string');
  assert((version >>> 0) === version);
  assert(Buffer.isBuffer(hash));

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  const out = POOL65;

  out[0] = version;

  const data = convert(out, 1, 5, hash, 0, 8, true);

  return serialize(hrp, data);
}

/**
 * Deserialize data from bech32 address.
 * @param {String} addr
 * @returns {Array}
 */

function decode(addr) {
  const [hrp, data] = deserialize(addr);

  if (data.length === 0 || data.length > 65)
    throw new Error('Invalid bech32 data length.');

  const version = data[0];

  if (version > 31)
    throw new Error('Invalid bech32 version.');

  const output = data; // Works because dstbits > srcbits.
  const hash = convert(output, 0, 8, data, 1, 5, false);

  if (hash.length < 2 || hash.length > 40)
    throw new Error('Invalid bech32 data length.');

  return [hrp, version, hash];
}

/**
 * Test whether a string is a bech32 string.
 * @param {String} addr
 * @returns {Boolean}
 */

function test(addr) {
  assert(typeof addr === 'string');

  try {
    decode(addr);
    return true;
  } catch (e) {
    return false;
  }
}

/*
 * Expose
 */

exports.native = 0;
exports.serialize = serialize;
exports.deserialize = deserialize;
exports.is = is;
exports.convertBits = convertBits;
exports.encode = encode;
exports.decode = decode;
exports.test = test;
}],
[/* 58 */ 'bcrypto', '/lib/blake2b-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * blake2b.js - blake2b for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(59 /* './js/blake2b' */);
}],
[/* 59 */ 'bcrypto', '/lib/js/blake2b.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * blake2b.js - BLAKE2b implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on dcposch/blakejs:
 *   Daniel Clemens Posch (CC0)
 *   https://github.com/dcposch/blakejs/blob/master/blake2b.js
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/BLAKE_(hash_function)
 *   https://tools.ietf.org/html/rfc7693
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/*
 * Constants
 */

const FINALIZED = 0x80000000;

const IV = new Uint32Array([
  0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85,
  0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
  0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c,
  0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19
]);

const SIGMA = new Uint8Array([
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
  0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
  0x1c, 0x14, 0x08, 0x10, 0x12, 0x1e, 0x1a, 0x0c,
  0x02, 0x18, 0x00, 0x04, 0x16, 0x0e, 0x0a, 0x06,
  0x16, 0x10, 0x18, 0x00, 0x0a, 0x04, 0x1e, 0x1a,
  0x14, 0x1c, 0x06, 0x0c, 0x0e, 0x02, 0x12, 0x08,
  0x0e, 0x12, 0x06, 0x02, 0x1a, 0x18, 0x16, 0x1c,
  0x04, 0x0c, 0x0a, 0x14, 0x08, 0x00, 0x1e, 0x10,
  0x12, 0x00, 0x0a, 0x0e, 0x04, 0x08, 0x14, 0x1e,
  0x1c, 0x02, 0x16, 0x18, 0x0c, 0x10, 0x06, 0x1a,
  0x04, 0x18, 0x0c, 0x14, 0x00, 0x16, 0x10, 0x06,
  0x08, 0x1a, 0x0e, 0x0a, 0x1e, 0x1c, 0x02, 0x12,
  0x18, 0x0a, 0x02, 0x1e, 0x1c, 0x1a, 0x08, 0x14,
  0x00, 0x0e, 0x0c, 0x06, 0x12, 0x04, 0x10, 0x16,
  0x1a, 0x16, 0x0e, 0x1c, 0x18, 0x02, 0x06, 0x12,
  0x0a, 0x00, 0x1e, 0x08, 0x10, 0x0c, 0x04, 0x14,
  0x0c, 0x1e, 0x1c, 0x12, 0x16, 0x06, 0x00, 0x10,
  0x18, 0x04, 0x1a, 0x0e, 0x02, 0x08, 0x14, 0x0a,
  0x14, 0x04, 0x10, 0x08, 0x0e, 0x0c, 0x02, 0x0a,
  0x1e, 0x16, 0x12, 0x1c, 0x06, 0x18, 0x1a, 0x00,
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
  0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
  0x1c, 0x14, 0x08, 0x10, 0x12, 0x1e, 0x1a, 0x0c,
  0x02, 0x18, 0x00, 0x04, 0x16, 0x0e, 0x0a, 0x06
]);

/**
 * BLAKE2b
 */

class BLAKE2b {
  constructor() {
    this.state = new Uint32Array(16);
    this.V = new Uint32Array(32);
    this.M = new Uint32Array(32);
    this.block = Buffer.alloc(128);
    this.size = 32;
    this.count = 0;
    this.pos = FINALIZED;
  }

  init(size, key) {
    if (size == null)
      size = 32;

    assert((size >>> 0) === size);
    assert(key == null || Buffer.isBuffer(key));

    if (size === 0 || size > 64)
      throw new Error('Bad output length.');

    if (key && key.length > 64)
      throw new Error('Bad key length.');

    const klen = key ? key.length : 0;

    for (let i = 0; i < 16; i++)
      this.state[i] = IV[i];

    this.size = size;
    this.count = 0;
    this.pos = 0;

    this.state[0] ^= 0x01010000 ^ (klen << 8) ^ this.size;

    if (klen > 0) {
      const block = Buffer.alloc(128, 0x00);

      key.copy(block, 0);

      this.update(block);
    }

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(!(this.pos & FINALIZED), 'Context is not initialized.');

    let off = 0;
    let len = data.length;

    if (len > 0) {
      const left = this.pos;
      const fill = 128 - left;

      if (len > fill) {
        this.pos = 0;

        data.copy(this.block, left, off, off + fill);

        this.count += 128;
        this._compress(this.block, 0, false);

        off += fill;
        len -= fill;

        while (len > 128) {
          this.count += 128;
          this._compress(data, off, false);
          off += 128;
          len -= 128;
        }
      }

      data.copy(this.block, this.pos, off, off + len);

      this.pos += len;
    }

    return this;
  }

  final() {
    assert(!(this.pos & FINALIZED), 'Context is not initialized.');

    this.count += this.pos;
    this.block.fill(0, this.pos, 128);
    this._compress(this.block, 0, true);
    this.pos = FINALIZED;

    const out = Buffer.alloc(this.size);

    for (let i = 0; i < this.size; i++)
      out[i] = this.state[i >>> 2] >>> (8 * (i & 3));

    for (let i = 0; i < 16; i++)
      this.state[i] = 0;

    for (let i = 0; i < 32; i++) {
      this.V[i] = 0;
      this.M[i] = 0;
    }

    for (let i = 0; i < 128; i++)
      this.block[i] = 0;

    return out;
  }

  _compress(block, off, last) {
    const {V, M} = this;

    for (let i = 0; i < 16; i++) {
      V[i] = this.state[i];
      V[i + 16] = IV[i];
    }

    // uint128
    V[24] ^= this.count;
    V[25] ^= this.count * (1 / 0x100000000);
    V[26] ^= 0;
    V[27] ^= 0;

    if (last) {
      // last block
      V[28] ^= -1;
      V[29] ^= -1;

      // last node
      V[29] ^= 0;
      V[30] ^= 0;
    }

    for (let i = 0; i < 32; i++) {
      M[i] = readU32(block, off);
      off += 4;
    }

    for (let i = 0; i < 12; i++) {
      G(V, M, 0, 8, 16, 24, SIGMA[i * 16 + 0], SIGMA[i * 16 + 1]);
      G(V, M, 2, 10, 18, 26, SIGMA[i * 16 + 2], SIGMA[i * 16 + 3]);
      G(V, M, 4, 12, 20, 28, SIGMA[i * 16 + 4], SIGMA[i * 16 + 5]);
      G(V, M, 6, 14, 22, 30, SIGMA[i * 16 + 6], SIGMA[i * 16 + 7]);
      G(V, M, 0, 10, 20, 30, SIGMA[i * 16 + 8], SIGMA[i * 16 + 9]);
      G(V, M, 2, 12, 22, 24, SIGMA[i * 16 + 10], SIGMA[i * 16 + 11]);
      G(V, M, 4, 14, 16, 26, SIGMA[i * 16 + 12], SIGMA[i * 16 + 13]);
      G(V, M, 6, 8, 18, 28, SIGMA[i * 16 + 14], SIGMA[i * 16 + 15]);
    }

    for (let i = 0; i < 16; i++)
      this.state[i] ^= V[i] ^ V[i + 16];
  }

  static hash() {
    return new BLAKE2b();
  }

  static hmac(size) {
    return new HMAC(BLAKE2b, 128, [size]);
  }

  static digest(data, size, key) {
    const {ctx} = BLAKE2b;

    ctx.init(size, key);
    ctx.update(data);

    return ctx.final();
  }

  static root(left, right, size, key) {
    if (size == null)
      size = 32;

    assert(Buffer.isBuffer(left) && left.length === size);
    assert(Buffer.isBuffer(right) && right.length === size);

    const {ctx} = BLAKE2b;

    ctx.init(size, key);
    ctx.update(left);
    ctx.update(right);

    return ctx.final();
  }

  static multi(x, y, z, size, key) {
    const {ctx} = BLAKE2b;

    ctx.init(size, key);
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final();
  }

  static mac(data, key, size) {
    return BLAKE2b.hmac(size).init(key).update(data).final();
  }
}

/*
 * Static
 */

BLAKE2b.native = 0;
BLAKE2b.id = 'BLAKE2B256';
BLAKE2b.size = 32;
BLAKE2b.bits = 256;
BLAKE2b.blockSize = 128;
BLAKE2b.zero = Buffer.alloc(32, 0x00);
BLAKE2b.ctx = new BLAKE2b();

/*
 * Helpers
 */

function sum64i(v, a, b) {
  const o0 = v[a + 0] + v[b + 0];
  const o1 = v[a + 1] + v[b + 1];
  const c = (o0 >= 0x100000000) | 0;

  v[a + 0] = o0;
  v[a + 1] = o1 + c;
}

function sum64w(v, a, b0, b1) {
  const o0 = v[a + 0] + b0;
  const o1 = v[a + 1] + b1;
  const c = (o0 >= 0x100000000) | 0;

  v[a + 0] = o0;
  v[a + 1] = o1 + c;
}

function G(v, m, a, b, c, d, ix, iy) {
  const x0 = m[ix + 0];
  const x1 = m[ix + 1];
  const y0 = m[iy + 0];
  const y1 = m[iy + 1];

  sum64i(v, a, b);
  sum64w(v, a, x0, x1);

  const xor0 = v[d + 0] ^ v[a + 0];
  const xor1 = v[d + 1] ^ v[a + 1];

  v[d + 0] = xor1;
  v[d + 1] = xor0;

  sum64i(v, c, d);

  const xor2 = v[b + 0] ^ v[c + 0];
  const xor3 = v[b + 1] ^ v[c + 1];

  v[b + 0] = (xor2 >>> 24) ^ (xor3 << 8);
  v[b + 1] = (xor3 >>> 24) ^ (xor2 << 8);

  sum64i(v, a, b);
  sum64w(v, a, y0, y1);

  const xor4 = v[d + 0] ^ v[a + 0];
  const xor5 = v[d + 1] ^ v[a + 1];

  v[d + 0] = (xor4 >>> 16) ^ (xor5 << 16);
  v[d + 1] = (xor5 >>> 16) ^ (xor4 << 16);

  sum64i(v, c, d);

  const xor6 = v[b + 0] ^ v[c + 0];
  const xor7 = v[b + 1] ^ v[c + 1];

  v[b + 0] = (xor7 >>> 31) ^ (xor6 << 1);
  v[b + 1] = (xor6 >>> 31) ^ (xor7 << 1);
}

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

/*
 * Expose
 */

module.exports = BLAKE2b;
}],
[/* 60 */ 'bcrypto', '/lib/sha3-browser.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * sha3.js - sha3 for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

module.exports = __node_require__(61 /* './js/sha3' */);
}],
[/* 61 */ 'bcrypto', '/lib/js/sha3.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * sha3.js - SHA3 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-3
 *   https://keccak.team/specifications.html
 *   https://csrc.nist.gov/projects/hash-functions/sha-3-project/sha-3-standardization
 *   http://dx.doi.org/10.6028/NIST.FIPS.202
 */

'use strict';

const Keccak = __node_require__(62 /* './keccak' */);

/**
 * SHA3
 */

class SHA3 extends Keccak {
  constructor() {
    super();
  }

  final() {
    return super.final(0x06, null);
  }

  static hash() {
    return new SHA3();
  }

  static hmac(bits) {
    return super.hmac(bits, 0x06, null);
  }

  static digest(data, bits) {
    return super.digest(data, bits, 0x06, null);
  }

  static root(left, right, bits) {
    return super.root(left, right, bits, 0x06, null);
  }

  static multi(x, y, z, bits) {
    return super.multi(x, y, z, bits, 0x06, null);
  }

  static mac(data, key, bits) {
    return super.mac(data, key, bits, 0x06, null);
  }
}

/*
 * Static
 */

SHA3.native = 0;
SHA3.id = 'SHA3_256';
SHA3.size = 32;
SHA3.bits = 256;
SHA3.blockSize = 136;
SHA3.zero = Buffer.alloc(32, 0x00);
SHA3.ctx = new SHA3();

/*
 * Expose
 */

module.exports = SHA3;
}],
[/* 62 */ 'bcrypto', '/lib/js/keccak.js', function(exports, module, __filename, __dirname, __meta) {
/*!
 * keccak.js - Keccak/SHA3 implementation for bcrypto
 * Copyright (c) 2017-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on emn178/js-sha3:
 *   Copyright (c) 2015-2017, Chen, Yi-Cyuan (MIT License).
 *   https://github.com/emn178/js-sha3
 *
 * Parts of this software are based on rhash/RHash:
 *   Copyright (c) 2005-2014, Aleksey Kravchenko
 *   https://github.com/rhash/RHash
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-3
 *   https://keccak.team/specifications.html
 *   https://csrc.nist.gov/projects/hash-functions/sha-3-project/sha-3-standardization
 *   http://dx.doi.org/10.6028/NIST.FIPS.202
 *   https://github.com/rhash/RHash/blob/master/librhash/sha3.c
 *   https://github.com/emn178/js-sha3/blob/master/src/sha3.js
 */

'use strict';

const assert = __node_require__(14 /* '../internal/assert' */);
const HMAC = __node_require__(17 /* '../internal/hmac' */);

/*
 * Constants
 */

const FINALIZED = 0x80000000;

const ROUND_CONST = new Uint32Array([
  0x00000001, 0x00000000, 0x00008082, 0x00000000,
  0x0000808a, 0x80000000, 0x80008000, 0x80000000,
  0x0000808b, 0x00000000, 0x80000001, 0x00000000,
  0x80008081, 0x80000000, 0x00008009, 0x80000000,
  0x0000008a, 0x00000000, 0x00000088, 0x00000000,
  0x80008009, 0x00000000, 0x8000000a, 0x00000000,
  0x8000808b, 0x00000000, 0x0000008b, 0x80000000,
  0x00008089, 0x80000000, 0x00008003, 0x80000000,
  0x00008002, 0x80000000, 0x00000080, 0x80000000,
  0x0000800a, 0x00000000, 0x8000000a, 0x80000000,
  0x80008081, 0x80000000, 0x00008080, 0x80000000,
  0x80000001, 0x00000000, 0x80008008, 0x80000000
]);

/**
 * Keccak
 */

class Keccak {
  constructor() {
    this.state = new Uint32Array(50);
    this.block = Buffer.alloc(200);
    this.bs = 136;
    this.pos = FINALIZED;
  }

  init(bits) {
    if (bits == null)
      bits = 256;

    assert((bits >>> 0) === bits);
    assert(bits >= 128);
    assert(bits <= 512);

    const rate = 1600 - bits * 2;

    assert(rate >= 0 && (rate & 63) === 0);

    this.bs = rate >>> 3;
    this.pos = 0;

    return this;
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    assert(!(this.pos & FINALIZED), 'Context is not initialized.');

    let len = data.length;
    let pos = this.pos;
    let off = 0;

    this.pos = (this.pos + len) % this.bs;

    if (pos > 0) {
      let want = this.bs - pos;

      if (want > len)
        want = len;

      data.copy(this.block, pos, off, off + want);

      pos += want;
      len -= want;
      off += want;

      if (pos < this.bs)
        return this;

      this._transform(this.block, 0);
    }

    while (len >= this.bs) {
      this._transform(data, off);
      off += this.bs;
      len -= this.bs;
    }

    if (len > 0)
      data.copy(this.block, 0, off, off + len);

    return this;
  }

  final(pad, len) {
    if (pad == null)
      pad = 0x01;

    if (len == null || len === 0)
      len = 100 - (this.bs >>> 1);

    assert((pad & 0xff) === pad);
    assert((len >>> 0) === len);
    assert(!(this.pos & FINALIZED), 'Context is not initialized.');

    this.block.fill(0, this.pos, this.bs);
    this.block[this.pos] |= pad;
    this.block[this.bs - 1] |= 0x80;
    this._transform(this.block, 0);
    this.pos = FINALIZED;

    assert(len <= this.bs);

    const out = Buffer.alloc(len);

    for (let i = 0; i < len; i++)
      out[i] = this.state[i >>> 2] >>> (8 * (i & 3));

    for (let i = 0; i < 50; i++)
      this.state[i] = 0;

    for (let i = 0; i < this.bs; i++)
      this.block[i] = 0;

    return out;
  }

  _transform(block, off) {
    const count = this.bs >>> 2;
    const s = this.state;

    for (let i = 0; i < count; i++)
      s[i] ^= readU32(block, off + i * 4);

    for (let n = 0; n < 48; n += 2) {
      const c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
      const c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
      const c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
      const c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
      const c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
      const c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
      const c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
      const c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
      const c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
      const c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

      const h0 = c8 ^ ((c2 << 1) | (c3 >>> 31));
      const l0 = c9 ^ ((c3 << 1) | (c2 >>> 31));
      const h1 = c0 ^ ((c4 << 1) | (c5 >>> 31));
      const l1 = c1 ^ ((c5 << 1) | (c4 >>> 31));
      const h2 = c2 ^ ((c6 << 1) | (c7 >>> 31));
      const l2 = c3 ^ ((c7 << 1) | (c6 >>> 31));
      const h3 = c4 ^ ((c8 << 1) | (c9 >>> 31));
      const l3 = c5 ^ ((c9 << 1) | (c8 >>> 31));
      const h4 = c6 ^ ((c0 << 1) | (c1 >>> 31));
      const l4 = c7 ^ ((c1 << 1) | (c0 >>> 31));

      s[0] ^= h0;
      s[1] ^= l0;
      s[10] ^= h0;
      s[11] ^= l0;
      s[20] ^= h0;
      s[21] ^= l0;
      s[30] ^= h0;
      s[31] ^= l0;
      s[40] ^= h0;
      s[41] ^= l0;

      s[2] ^= h1;
      s[3] ^= l1;
      s[12] ^= h1;
      s[13] ^= l1;
      s[22] ^= h1;
      s[23] ^= l1;
      s[32] ^= h1;
      s[33] ^= l1;
      s[42] ^= h1;
      s[43] ^= l1;

      s[4] ^= h2;
      s[5] ^= l2;
      s[14] ^= h2;
      s[15] ^= l2;
      s[24] ^= h2;
      s[25] ^= l2;
      s[34] ^= h2;
      s[35] ^= l2;
      s[44] ^= h2;
      s[45] ^= l2;

      s[6] ^= h3;
      s[7] ^= l3;
      s[16] ^= h3;
      s[17] ^= l3;
      s[26] ^= h3;
      s[27] ^= l3;
      s[36] ^= h3;
      s[37] ^= l3;
      s[46] ^= h3;
      s[47] ^= l3;

      s[8] ^= h4;
      s[9] ^= l4;
      s[18] ^= h4;
      s[19] ^= l4;
      s[28] ^= h4;
      s[29] ^= l4;
      s[38] ^= h4;
      s[39] ^= l4;
      s[48] ^= h4;
      s[49] ^= l4;

      const b0 = s[0];
      const b1 = s[1];
      const b32 = (s[11] << 4) | (s[10] >>> 28);
      const b33 = (s[10] << 4) | (s[11] >>> 28);
      const b14 = (s[20] << 3) | (s[21] >>> 29);
      const b15 = (s[21] << 3) | (s[20] >>> 29);
      const b46 = (s[31] << 9) | (s[30] >>> 23);
      const b47 = (s[30] << 9) | (s[31] >>> 23);
      const b28 = (s[40] << 18) | (s[41] >>> 14);
      const b29 = (s[41] << 18) | (s[40] >>> 14);
      const b20 = (s[2] << 1) | (s[3] >>> 31);
      const b21 = (s[3] << 1) | (s[2] >>> 31);
      const b2 = (s[13] << 12) | (s[12] >>> 20);
      const b3 = (s[12] << 12) | (s[13] >>> 20);
      const b34 = (s[22] << 10) | (s[23] >>> 22);
      const b35 = (s[23] << 10) | (s[22] >>> 22);
      const b16 = (s[33] << 13) | (s[32] >>> 19);
      const b17 = (s[32] << 13) | (s[33] >>> 19);
      const b48 = (s[42] << 2) | (s[43] >>> 30);
      const b49 = (s[43] << 2) | (s[42] >>> 30);
      const b40 = (s[5] << 30) | (s[4] >>> 2);
      const b41 = (s[4] << 30) | (s[5] >>> 2);
      const b22 = (s[14] << 6) | (s[15] >>> 26);
      const b23 = (s[15] << 6) | (s[14] >>> 26);
      const b4 = (s[25] << 11) | (s[24] >>> 21);
      const b5 = (s[24] << 11) | (s[25] >>> 21);
      const b36 = (s[34] << 15) | (s[35] >>> 17);
      const b37 = (s[35] << 15) | (s[34] >>> 17);
      const b18 = (s[45] << 29) | (s[44] >>> 3);
      const b19 = (s[44] << 29) | (s[45] >>> 3);
      const b10 = (s[6] << 28) | (s[7] >>> 4);
      const b11 = (s[7] << 28) | (s[6] >>> 4);
      const b42 = (s[17] << 23) | (s[16] >>> 9);
      const b43 = (s[16] << 23) | (s[17] >>> 9);
      const b24 = (s[26] << 25) | (s[27] >>> 7);
      const b25 = (s[27] << 25) | (s[26] >>> 7);
      const b6 = (s[36] << 21) | (s[37] >>> 11);
      const b7 = (s[37] << 21) | (s[36] >>> 11);
      const b38 = (s[47] << 24) | (s[46] >>> 8);
      const b39 = (s[46] << 24) | (s[47] >>> 8);
      const b30 = (s[8] << 27) | (s[9] >>> 5);
      const b31 = (s[9] << 27) | (s[8] >>> 5);
      const b12 = (s[18] << 20) | (s[19] >>> 12);
      const b13 = (s[19] << 20) | (s[18] >>> 12);
      const b44 = (s[29] << 7) | (s[28] >>> 25);
      const b45 = (s[28] << 7) | (s[29] >>> 25);
      const b26 = (s[38] << 8) | (s[39] >>> 24);
      const b27 = (s[39] << 8) | (s[38] >>> 24);
      const b8 = (s[48] << 14) | (s[49] >>> 18);
      const b9 = (s[49] << 14) | (s[48] >>> 18);

      s[0] = b0 ^ (~b2 & b4);
      s[1] = b1 ^ (~b3 & b5);
      s[10] = b10 ^ (~b12 & b14);
      s[11] = b11 ^ (~b13 & b15);
      s[20] = b20 ^ (~b22 & b24);
      s[21] = b21 ^ (~b23 & b25);
      s[30] = b30 ^ (~b32 & b34);
      s[31] = b31 ^ (~b33 & b35);
      s[40] = b40 ^ (~b42 & b44);
      s[41] = b41 ^ (~b43 & b45);
      s[2] = b2 ^ (~b4 & b6);
      s[3] = b3 ^ (~b5 & b7);
      s[12] = b12 ^ (~b14 & b16);
      s[13] = b13 ^ (~b15 & b17);
      s[22] = b22 ^ (~b24 & b26);
      s[23] = b23 ^ (~b25 & b27);
      s[32] = b32 ^ (~b34 & b36);
      s[33] = b33 ^ (~b35 & b37);
      s[42] = b42 ^ (~b44 & b46);
      s[43] = b43 ^ (~b45 & b47);
      s[4] = b4 ^ (~b6 & b8);
      s[5] = b5 ^ (~b7 & b9);
      s[14] = b14 ^ (~b16 & b18);
      s[15] = b15 ^ (~b17 & b19);
      s[24] = b24 ^ (~b26 & b28);
      s[25] = b25 ^ (~b27 & b29);
      s[34] = b34 ^ (~b36 & b38);
      s[35] = b35 ^ (~b37 & b39);
      s[44] = b44 ^ (~b46 & b48);
      s[45] = b45 ^ (~b47 & b49);
      s[6] = b6 ^ (~b8 & b0);
      s[7] = b7 ^ (~b9 & b1);
      s[16] = b16 ^ (~b18 & b10);
      s[17] = b17 ^ (~b19 & b11);
      s[26] = b26 ^ (~b28 & b20);
      s[27] = b27 ^ (~b29 & b21);
      s[36] = b36 ^ (~b38 & b30);
      s[37] = b37 ^ (~b39 & b31);
      s[46] = b46 ^ (~b48 & b40);
      s[47] = b47 ^ (~b49 & b41);
      s[8] = b8 ^ (~b0 & b2);
      s[9] = b9 ^ (~b1 & b3);
      s[18] = b18 ^ (~b10 & b12);
      s[19] = b19 ^ (~b11 & b13);
      s[28] = b28 ^ (~b20 & b22);
      s[29] = b29 ^ (~b21 & b23);
      s[38] = b38 ^ (~b30 & b32);
      s[39] = b39 ^ (~b31 & b33);
      s[48] = b48 ^ (~b40 & b42);
      s[49] = b49 ^ (~b41 & b43);

      s[0] ^= ROUND_CONST[n + 0];
      s[1] ^= ROUND_CONST[n + 1];
    }
  }

  static hash() {
    return new Keccak();
  }

  static hmac(bits, pad, len) {
    if (bits == null)
      bits = 256;

    assert((bits >>> 0) === bits);

    const rate = 1600 - bits * 2;

    assert(rate >= 0 && (rate & 63) === 0);

    return new HMAC(Keccak, rate >>> 3, [bits], [pad, len]);
  }

  static digest(data, bits, pad, len) {
    return Keccak.ctx.init(bits).update(data).final(pad, len);
  }

  static root(left, right, bits, pad, len) {
    if (bits == null)
      bits = 256;

    if (len == null)
      len = 0;

    if (len === 0)
      len = bits >>> 3;

    assert((bits >>> 0) === bits);
    assert((bits & 7) === 0);
    assert((len >>> 0) === len);
    assert(Buffer.isBuffer(left) && left.length === len);
    assert(Buffer.isBuffer(right) && right.length === len);

    return Keccak.ctx.init(bits).update(left).update(right).final(pad, len);
  }

  static multi(x, y, z, bits, pad, len) {
    const {ctx} = Keccak;

    ctx.init(bits);
    ctx.update(x);
    ctx.update(y);

    if (z)
      ctx.update(z);

    return ctx.final(pad, len);
  }

  static mac(data, key, bits, pad, len) {
    return Keccak.hmac(bits, pad, len).init(key).update(data).final();
  }
}

/*
 * Static
 */

Keccak.native = 0;
Keccak.id = 'KECCAK256';
Keccak.size = 32;
Keccak.bits = 256;
Keccak.blockSize = 136;
Keccak.zero = Buffer.alloc(32, 0x00);
Keccak.ctx = new Keccak();

/*
 * Helpers
 */

function readU32(data, off) {
  return (data[off++]
        + data[off++] * 0x100
        + data[off++] * 0x10000
        + data[off] * 0x1000000);
}

/*
 * Expose
 */

module.exports = Keccak;
}]
];

var __node_cache__ = [];

function __node_error__(location) {
  var err = new Error('Cannot find module \'' + location + '\'');
  err.code = 'MODULE_NOT_FOUND';
  throw err;
}

function __node_require__(id) {
  if ((id >>> 0) !== id || id > __node_modules__.length)
    return __node_error__(id);

  while (__node_cache__.length <= id)
    __node_cache__.push(null);

  var cache = __node_cache__[id];

  if (cache)
    return cache.exports;

  var mod = __node_modules__[id];
  var name = mod[0];
  var path = mod[1];
  var func = mod[2];
  var meta;

  var _exports = exports;
  var _module = module;

  if (id !== 0) {
    _exports = {};
    _module = {
      id: '/' + name + path,
      exports: _exports,
      parent: module.parent,
      filename: module.filename,
      loaded: false,
      children: module.children,
      paths: module.paths
    };
  }

  __node_cache__[id] = _module;

  try {
    func.call(_exports, _exports, _module,
              __filename, __dirname, meta);
  } catch (e) {
    __node_cache__[id] = null;
    throw e;
  }

  __node_modules__[id] = null;

  if (id !== 0)
    _module.loaded = true;

  return _module.exports;
}

__node_require__(0);
