/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');
const deepEqual = require('./util.js').deepEqual;

test('ecdsa-examples verify ecdsa-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/ecdsa-examples/ecdsa-01.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('ecdsa-examples verify ecdsa-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/ecdsa-examples/ecdsa-02.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('create ecdsa-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/ecdsa-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signers = [{
    'key': {
      'd': base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    'u': example.input.sign.signers[0].unprotected,
    'p': example.input.sign.signers[0].protected
  }];

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signers
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('verify ecdsa-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/ecdsa-01.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('create sign-pass-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    'key': {
      'd': base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    'u': example.input.sign.signers[0].unprotected,
    'p': example.input.sign.signers[0].protected
  }];

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signers
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create sign-pass-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-02.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    'key': {
      'd': base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    'u': example.input.sign.signers[0].unprotected,
    'p': example.input.sign.signers[0].protected,
    'externalAAD': Buffer.from(example.input.sign.signers[0].external, 'hex')
  }];

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signers,
    { 'encodep': 'empty' }
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create sign-pass-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-03.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    'key': {
      'd': base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    'u': example.input.sign.signers[0].unprotected,
    'p': example.input.sign.signers[0].protected
  }];

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signers,
    {
      'encodep': 'empty',
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

test('verify sign-pass-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify sign-pass-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-02.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    },
    'externalAAD': Buffer.from(example.input.sign.signers[0].external, 'hex')
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify sign-pass-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-03.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify sign-fail-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-01.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unexpected cbor tag, \'998\'');
    });
});

test('verify sign-fail-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-02.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature missmatch');
    });
});

test('verify sign-fail-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-03.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, -999');
    });
});

test('verify sign-fail-04', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-04.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, unknown');
    });
});

test('verify sign-fail-06', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-06.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature missmatch');
    });
});

test('verify sign-fail-07', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-07.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature missmatch');
    });
});
