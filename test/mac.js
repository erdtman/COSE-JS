/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');

test('create mac-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-01.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('create mac-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-02.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const external = Buffer.from(example.input.mac0.external, 'hex');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = {'encodep': 'empty'};

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}],
    external,
    options)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('create mac-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-03.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = {'encodep': 'empty',
    'excludetag': true};

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}],
    null,
    options)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf);
    const expected = cbor.decode(example.output.cbor);

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('verify mac-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify mac-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-02.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const external = Buffer.from(example.input.mac0.external, 'hex');

  return cose.mac.read(example.output.cbor,
    key,
    external)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify mac-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-03.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify mac-fail-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Unexpected cbor tag, \'992\'');
  });
});

test('verify mac-fail-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-02.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Tag mismatch');
  });
});

test('verify mac-fail-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-03.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Unknown algorithm, -999');
  });
});

test('verify mac-fail-04', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-04.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Unknown algorithm, Unknown');
  });
});

test('verify mac-fail-06', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-06.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Tag mismatch');
  });
});

test('verify mac-fail-07', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-07.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Tag mismatch');
  });
});

test('create HMac-enc-01', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-01.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('create HMac-enc-02', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-02.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('create HMac-enc-03', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-03.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

// TODO add create HMac-enc-04

test('create HMac-enc-05', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-05.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('verify HMac-enc-01', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-enc-02', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-02.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-enc-03', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-03.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

// TODO add verify HMac-enc-05

test('verify HMac-enc-05', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-05.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});
