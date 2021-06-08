/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const jwkToPem = require('jwk-to-pem');
const cbor = require('cbor');
const deepEqual = require('./util.js').deepEqual;

function hexToB64 (hex) {
  return Buffer.from(hex, 'hex').toString('base64');
}

test('create rsa-pkcs-01', (t) => {
  const example = jsonfile.readFileSync('test/rsa-pkcs-examples/rsa-pkcs-01.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const testKey = example.input.sign0.key;
  const signer = {
    'key': jwkToPem({
      'kty': testKey.kty,
      'n': hexToB64(testKey.n_hex),
      'e': hexToB64(testKey.e_hex),
      'd': hexToB64(testKey.d_hex),
      'p': hexToB64(testKey.p_hex),
      'q': hexToB64(testKey.q_hex),
      'dp': hexToB64(testKey.dP_hex),
      'dq': hexToB64(testKey.dQ_hex),
      'qi': hexToB64(testKey.qi_hex)
    }, { private: true })
  };

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signer,
    {
      'excludetag': true
    }
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create rsa-pkcs-01 Sync', (t) => {
  const example = jsonfile.readFileSync('test/rsa-pkcs-examples/rsa-pkcs-01.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const testKey = example.input.sign0.key;
  const signer = {
    'key': jwkToPem({
      'kty': testKey.kty,
      'n': hexToB64(testKey.n_hex),
      'e': hexToB64(testKey.e_hex),
      'd': hexToB64(testKey.d_hex),
      'p': hexToB64(testKey.p_hex),
      'q': hexToB64(testKey.q_hex),
      'dp': hexToB64(testKey.dP_hex),
      'dq': hexToB64(testKey.dQ_hex),
      'qi': hexToB64(testKey.qi_hex)
    }, { private: true })
  };

  const buf = cose.sign.createSync(
    { 'p': p, 'u': u },
    plaintext,
    signer,
    {
      'excludetag': true
    }
  );
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  t.true(deepEqual(actual, expected));
});

test('verify rsa-pkcs-01', (t) => {
  const example = jsonfile.readFileSync('test/rsa-pkcs-examples/rsa-pkcs-01.json');

  const testKey = example.input.sign0.key;

  const verifier = {
    'key': jwkToPem({
      'kty': testKey.kty,
      'n': hexToB64(testKey.n_hex),
      'e': hexToB64(testKey.e_hex)
    })
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier,
    {
      'defaultType': cose.sign.Sign1Tag
    })
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify rsa-pkcs-01 Sync', (t) => {
  const example = jsonfile.readFileSync('test/rsa-pkcs-examples/rsa-pkcs-01.json');

  const testKey = example.input.sign0.key;

  const verifier = {
    'key': jwkToPem({
      'kty': testKey.kty,
      'n': hexToB64(testKey.n_hex),
      'e': hexToB64(testKey.e_hex)
    })
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = cose.sign.verifySync(
    signature,
    verifier,
    {
      'defaultType': cose.sign.Sign1Tag
    });

  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  t.is(buf.toString('utf8'), example.input.plaintext);
});
