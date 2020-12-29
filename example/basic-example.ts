import {
  SimplePfsStream
} from '../src/index';

import * as cc from 'commons-crypto';

const keyAlgorithm = cc.createAsymmetricAlgorithm(cc.AsymmetricAlgorithmType.ec, 'secp256k1');
const keyPair = keyAlgorithm.generateKeyPair();

const server = new SimplePfsStream({
  server: true,
  privateKey: keyPair.privateKey,
  signatureAlgorithm: '1.2.840.10045.4.3.2',
  send(buf) {
    console.log('server: send: ', buf);
    return client.process(buf);
  },
  handshaked() {
    console.log('server: handshaked');
    server.send({
      hello: 'hello world from server'
    });
  },
  dataReady(buf) {
    console.log('server: dataReady:', buf);
  },
  closed() {
    console.error('server: closed');
  },
  error(err) {
    console.error('server: error: ', err);
  }
});
const client = new SimplePfsStream({
  server: false,
  handshakeVerifier(ctx) {
    return Promise.resolve(true);
  },
  send(buf) {
    console.log('client: send: ', buf);
    return server.process(buf);
  },
  handshaked() {
    console.log('client: handshaked');
    client.send({
      hello: 'hello world from client'
    });
  },
  closed() {
    console.error('client: closed');
  },
  error(err) {
    console.error('client: error: ', err);
  }
});

client.handshake();

client.on('data', (buf) => console.log('client buf : ', buf));

