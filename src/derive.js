'use strict';

const HDPublicKey = require('hsd/lib/hd/public');
const Address = require('hsd/lib/primitives/address');
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

// For some reason when bpkg'ed with -browser modules, we need to call
// this once as a throwaway before actually using it.
// The first function call FAILS because entropy can not be found to
// "pregenerate a random blinding value" as part of the ECDSA precomputation.
// For whatever reason, the function call succeeds from here on.
// This is either a bug in bcrypto or bpkg, exposing an inconguity
// with the -browser module.
// See https://github.com/handshake-org/hsd/issues/700
acct.derive(0);

const recv = acct.derive(0);

function addr() {
  const indexFile = path.join(__dirname, '..', 'log', 'hip2-index');
  let index = 0;
  try {
    index = parseInt(fs.readFileSync(indexFile, 'utf-8'));
  } catch (e) {
    ;
  }

  fs.writeFileSync(indexFile, String(index + 1), 'utf-8');

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
