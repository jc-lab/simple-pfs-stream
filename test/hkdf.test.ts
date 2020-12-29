import * as chai from 'chai';
import * as cc from 'commons-crypto';
import {hkdf} from '../src/hkdf';

describe('HKDF Test', function () {
  it('SHA-256 Test Vector', function () {
    const hash = cc.createHash('sha256');
    if (!hash) {
      throw new Error('hash is null');
    }
    const ikm = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex');
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
    const length = 42;
    const output = hkdf(hash, length, ikm, salt, info);

    const expected = Buffer.from('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865', 'hex');
    chai.expect(output).eql(expected);
  });
});
