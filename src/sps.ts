import * as stream from 'stream';
import * as cc from 'commons-crypto';
import * as crypto from 'crypto';
import * as elliptic from 'elliptic';
import payload from './model/payload';
import {hkdf} from './hkdf';
import PayloadType = payload.PayloadType;
import {AlertError} from './error';

export type JsonObject = Record<string, any>;
export type JsonAny = JsonObject | any[];
export type RawBytes = Buffer;

export interface CommonConnectionOptions {
  handshaked?: () => void;
  send: (buf: JsonObject) => Promise<void> | void;
  dataReady?: (buf: JsonAny) => Promise<void> | void;
  closed?: () => void;
  error?: (err: any) => void;
}

export type HandshakeInterceptor = (clientHello: payload.ClientHello, mutableServerHelloEncrypted: payload.ServerHelloEncrypted) => Promise<void> | void;
export interface ServerConnectionOptions extends CommonConnectionOptions {
  server: true;
  privateKey: cc.AsymmetricKeyObject;
  serverCertificate?: any;
  signatureAlgorithm: string;
  handshakeInterceptor?: HandshakeInterceptor;
}

export interface HandshakeVerificationContext {
  serverPublicKey: cc.AsymmetricKeyObject;
  serverHelloEncrypted: Readonly<payload.ServerHelloEncrypted>;
  serverCertificate: any;
  extensions: any;
}

export type HandshakeVerifier = (ctx: HandshakeVerificationContext) => Promise<boolean>;
export interface ClientConnectionOptions extends CommonConnectionOptions {
  server: false;
  handshakeVerifier: HandshakeVerifier;
}

type ConnetionOptions = ServerConnectionOptions | ClientConnectionOptions;

export enum HandshakeState {
  NotStarted,
  ClientHello,
  ServerHello,
  Handshaked,
  Final
}

const availableUnwrappedPayloads: payload.PayloadType[] = [
  payload.PayloadType.ClientHello,
  payload.PayloadType.ServerHello,
  payload.PayloadType.WrappedData
];
const availableWrappedPayloads: payload.PayloadType[] = [
  payload.PayloadType.ClientFinishHandshake,
  payload.PayloadType.TrafficKeyUpdate,
  payload.PayloadType.ApplicationData
];

function publicKeyToBase64(key: elliptic.ec.KeyPair | elliptic.curve.base.BasePoint): string {
  const point: elliptic.curve.base.BasePoint =
    ('getPublic' in key) ? key.getPublic() : key;
  return Buffer.from(point.encodeCompressed('array')).toString('base64');
}

function base64ToPublicKey(ec: elliptic.ec, encoded: string): elliptic.ec.KeyPair {
  return ec.keyFromPublic(Buffer.from(encoded, 'base64'));
}

function safeBufferConcat(buffers: (Buffer | undefined)[]): Buffer {
  return Buffer.concat(
    buffers.filter(v => !!v) as Buffer[]
  );
}

interface DeriveSecretOptions {
  length?: number | false;
  label: string;
  seed?: Buffer;
  secret?: Buffer;
  hash?: cc.Hash;
  serverNonce?: Buffer;
  clientNonce?: Buffer;
}

/**
 * @example See below
 * ```typescript
 * type JsonObject = Record<string, any>;
 * const rawSocket = something;
 * const sps = new SimplePfsStream({
 *   ...,
 *   send(buf: JsonObject): Promise<void> {
 *     // raw data (encrypted) is ready to be sent to the server
 *     return rawSocket.send(buf);
 *   },
 *   handshaked() {
 *     // handshake completed
 *   },
 *   dataReady(buf: Buffer) {
 *     // clear data from the server is ready
 *     console.log('received:', buf.toString());
 *   },
 *   closed() {
 *     console.log('connection closed');
 *   },
 *   error(err: any) {
 *     console.log('error:', err);
 *   }
 * });
 * rawSocket.on('data', (buf: JsonObject | Buffer) => sps.process(buf));
 * sps.handshake(); // start handshake
 * ```
 */
export class SimplePfsStream extends stream.Duplex {
  private _privateKey!: cc.AsymmetricKeyObject;
  private _opts: ConnetionOptions;
  private _handshakeState: HandshakeState = HandshakeState.NotStarted;
  private _serverNonce!: Buffer;
  private _clientNonce!: Buffer;
  private _connectionPrfHash!: cc.Hash;
  private _connectionEncAlgo!: string;
  private _connectionEncBase!: cc.Cipher;
  private _ephemeralAlgorithm!: cc.AsymmetricKeyAlgorithm;
  private _ephemeralPrivateKey!: cc.AsymmetricKeyObject;
  private _masterSecret!: Buffer;
  private _wrappedTrafficSecret!: Buffer;
  private _wrappedTrafficKeyIV!: {
    key: Buffer;
    iv: Buffer
  };

  private static payloadHandlers: Record<payload.PayloadType, (p: any) => Promise<void>> = {
    [payload.PayloadType.Alert]: SimplePfsStream.prototype._alertProcess,
    [payload.PayloadType.ClientHello]: SimplePfsStream.prototype._clientHelloProcess,
    [payload.PayloadType.ServerHello]: SimplePfsStream.prototype._serverHelloProcess,
    [payload.PayloadType.WrappedData]: SimplePfsStream.prototype._wrappedDataProcess,
    [payload.PayloadType.ClientFinishHandshake]: SimplePfsStream.prototype._clientFinishHandshakeProcess,
    [payload.PayloadType.TrafficKeyUpdate]: SimplePfsStream.prototype._trafficKeyUpdateProcess,
    [payload.PayloadType.ApplicationData]: SimplePfsStream.prototype._applicationDataProcess
  };

  public constructor(opts: ConnetionOptions) {
    super({
      objectMode: true
    });
    this._opts = opts;
    if (opts.server) {
      this._privateKey = opts.privateKey;
    }
  }

  private _deriveSecret(options: DeriveSecretOptions): Buffer {
    const hash = options.hash || this._connectionPrfHash;
    const secret = options.secret || this._masterSecret;
    const serverNonce = options.serverNonce || this._serverNonce;
    const clientNonce = options.clientNonce || this._clientNonce;
    const msg: Buffer[] = [
      Buffer.from(options.label)
    ];
    msg.push(clientNonce);
    msg.push(serverNonce);
    if (options.seed) msg.push(options.seed);
    const length = options.length || hash.outputSize;
    return hkdf(hash, length, secret, Buffer.concat(msg));
  }
  private _deriveKeyAndIV(secret: Buffer, cipher: cc.Cipher | cc.Decipher, options?: Partial<DeriveSecretOptions>): { key: Buffer, iv: Buffer } {
    const key = this._deriveSecret({
      ...options,
      length: cipher.keySize / 8,
      label: 'key',
      secret: secret
    });
    const iv = this._deriveSecret({
      ...options,
      length: cipher.blockSize / 8,
      label: 'iv',
      secret: secret
    });
    return {key, iv};
  }

  public process(buf: payload.Payload | JsonObject | RawBytes | string): Promise<void> {
    let payload: payload.Payload;
    if (typeof buf === 'string') {
      payload = JSON.parse(buf);
    } else if (Buffer.isBuffer(buf)) {
      payload = JSON.parse(buf.toString('utf8'));
    } else {
      payload = buf as payload.Payload;
    }
    if (availableUnwrappedPayloads.findIndex(v => v === payload.$pt) < 0) {
      return Promise.reject(new Error('Unknown Payload'));
    }
    const handler = payload.$pt && SimplePfsStream.payloadHandlers[payload.$pt as payload.PayloadType];
    if (!handler) {
      return Promise.reject(new Error('Unknown Payload'));
    }
    return (handler.call(this, payload) as Promise<void>)
      .catch((err) => {
        if (this._opts.error) this._opts.error(err);
        else Promise.reject(err);
      });
  }

  public disconnect() {
    //TODO: send Finish payload
    return Promise.resolve()
      .then(() => this.emitClose());
  }

  public emitClose() {
    this._cleanup();
    this.emit('close');
    if (this._opts.closed)
      this._opts.closed();
  }

  public handshake(): Promise<void> {
    if (this._opts.server) {
      return Promise.reject(new Error('Not a client'));
    }

    this._cleanup();

    const ephemeralAlgorithm = cc.createAsymmetricAlgorithm(cc.AsymmetricAlgorithmType.ec, 'curve25519');
    const ephemeralKeyPair = ephemeralAlgorithm.generateKeyPair();
    const nonce: Buffer = crypto.randomBytes(16);

    const clientHello: payload.ClientHello = {
      $pt: payload.PayloadType.ClientHello,
      ephemeralAlgorithm: ephemeralAlgorithm.algorithmOid,
      ephemeralPublicKey: ephemeralKeyPair.publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
      availEncAlgo: ['2.16.840.1.101.3.4.1.46', '2.16.840.1.101.3.4.1.26', '2.16.840.1.101.3.4.1.6'],
      availPrfAlgo: ['1.2.840.10045.4.3.3', '2.16.840.1.101.3.4.2.1'],
      nonce: nonce.toString('base64')
    };

    this._ephemeralAlgorithm = ephemeralAlgorithm;
    this._ephemeralPrivateKey = ephemeralKeyPair.privateKey;
    this._clientNonce = nonce;

    this._handshakeState = HandshakeState.ClientHello;
    return Promise.resolve(this._opts.send(clientHello));
  }

  // public trafficKeyUpdate(): Promise<void> {
  //   return this._trafficKeyUpdate();
  // }

  public sendAlert(alert: payload.Alert): Promise<void> {
    return Promise.resolve(this._opts.send(alert));
  }

  public send(data: JsonObject): Promise<void> {
    if (this._handshakeState !== HandshakeState.Handshaked) {
      return Promise.reject(new Error('not handshaked'));
    }
    return this._wrapAndSend({
      $pt: PayloadType.ApplicationData,
      data: data
    } as payload.ApplicationData);
  }

  private _cleanup() {
    this._handshakeState = HandshakeState.NotStarted;
    this._serverNonce = undefined as any;
    this._clientNonce = undefined as any;
    this._connectionPrfHash = undefined as any;
    this._connectionEncAlgo = undefined as any;
    this._connectionEncBase = undefined as any;
    this._ephemeralAlgorithm = undefined as any;
    this._ephemeralPrivateKey = undefined as any;
    this._masterSecret = undefined as any;
    this._wrappedTrafficSecret = undefined as any;
    this._wrappedTrafficKeyIV = undefined as any;
  }

  public _alertProcess(alert: payload.Alert): Promise<void> {
    if (this._opts.error)
      this._opts.error(new AlertError(alert));
    return Promise.resolve();
  }

  public _clientHelloProcess(clientHello: payload.ClientHello): Promise<void> {
    if (this._handshakeState !== HandshakeState.NotStarted) {
      return Promise.resolve();
    }

    this._handshakeState = HandshakeState.ClientHello;

    const opts = this._opts as ServerConnectionOptions;
    const serverNonce: Buffer = crypto.randomBytes(16);

    const applicationTrafficSecretSalt = crypto.randomBytes(32);

    let remoteEphemeralKey: cc.AsymmetricKeyObject;

    try {
      remoteEphemeralKey = cc.createAsymmetricKey({
        format: 'der',
        type: 'spki',
        key: Buffer.from(clientHello.ephemeralPublicKey, 'base64')
      });
    } catch (e) {
      const alert: payload.Alert = {
        $pt: payload.PayloadType.Alert,
        code: 'E_NOT_SUPPORTED_EPHEMERAL_ALGORITHM',
        message: `ephemeral algorithm [${clientHello.ephemeralAlgorithm}] is not supported`
      };
      this.sendAlert(alert);
      return Promise.reject(new AlertError(alert));
    }

    const ephemeralAlgorithm = remoteEphemeralKey.getKeyAlgorithm();
    const ephemeralKeyPair = ephemeralAlgorithm.generateKeyPair();
    const masterSecret = ephemeralKeyPair.privateKey.dhComputeSecret(remoteEphemeralKey);

    const encAlgo = '2.16.840.1.101.3.4.1.46';
    const prfAlgo = '2.16.840.1.101.3.4.2.1';

    const cipher = cc.createCipher(encAlgo);
    if (!cipher) {
      return Promise.reject(new Error('cipher != null'));
    }
    const dataToBeEncrypted: payload.ServerHelloEncrypted = {
      applicationTrafficSecretSalt: applicationTrafficSecretSalt.toString('base64'),
      serverCertificate: opts.serverCertificate
    };
    return Promise.resolve()
      .then(() => {
        if (opts.handshakeInterceptor) {
          return opts.handshakeInterceptor(clientHello, dataToBeEncrypted);
        }
      })
      .then(() => {
        try {
          this._connectionEncAlgo = encAlgo;
          this._connectionPrfHash = cc.createHash(prfAlgo) as cc.Hash;
          this._connectionEncBase = cc.createCipher(encAlgo) as cc.Cipher;
          this._masterSecret = masterSecret;
          this._serverNonce = serverNonce;
          this._clientNonce = Buffer.from(clientHello.nonce, 'base64');

          const handshakeSecret = this._deriveSecret({
            label: 'server-handshake'
          });
          const handshakeKeyIV = this._deriveKeyAndIV(handshakeSecret, cipher);
          cipher.init({
            ...handshakeKeyIV
          });
          const encodedEncryptedData = safeBufferConcat([
            cipher.update(Buffer.from(JSON.stringify(dataToBeEncrypted))),
            cipher.final()
          ]);

          const protectedData: payload.ServerHelloProtected = {
            ephemeralPublicKey: ephemeralKeyPair.publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
            encAlgo: encAlgo,
            prfAlgo: prfAlgo,
            nonce: serverNonce.toString('base64'),
            authTag: cipher.getAuthTag().toString('base64')
          };
          const encodedProtected = Buffer.from(JSON.stringify(protectedData));

          const signer = cc.createSignatureByAlgorithm(opts.signatureAlgorithm) as cc.Signature;
          signer.init(this._privateKey);
          signer.write(encodedProtected);
          signer.write(encodedEncryptedData);
          signer.end();

          const signature = signer.sign();
          const serverPublicKey = this._privateKey.toPublicKey();

          const serverHello: payload.ServerHello = {
            $pt: payload.PayloadType.ServerHello,
            signatureAlgorithm: '1.2.840.10045.4.3.4',
            serverPublicKey: serverPublicKey.export({type: 'spki', format: 'der'}).toString('base64'),
            protected: encodedProtected.toString('base64'),
            encrypted: encodedEncryptedData.toString('base64'),
            signature: signature.toString('base64')
          };

          this._clientNonce = Buffer.from(clientHello.nonce, 'base64');
          this._serverNonce = serverNonce;

          const wrappedTrafficSecret = this._deriveSecret({
            label: 'wrapped-traffic',
            seed: applicationTrafficSecretSalt
          });
          this._setApplicationTrafficSecret(wrappedTrafficSecret);

          this._handshakeState = HandshakeState.ServerHello;
          return this._opts.send(serverHello);
        } catch (e) {
          return Promise.reject(e);
        }
      });
  }

  public _serverHelloProcess(serverHello: payload.ServerHello): Promise<void> {
    if (this._handshakeState !== HandshakeState.ClientHello) {
      return Promise.resolve();
    }

    const opts = this._opts as ClientConnectionOptions;
    let protectedData: payload.ServerHelloProtected;
    let masterSecret: Buffer;
    let connectionPrfHash: cc.Hash;

    this._handshakeState = HandshakeState.ServerHello;

    return Promise.resolve()
      .then(() => {
        try {
          const serverPublicKey = cc.createAsymmetricKey({
            type: 'spki',
            key: Buffer.from(serverHello.serverPublicKey, 'base64')
          });

          const encodedProtectedData = Buffer.from(serverHello.protected, 'base64');
          const encodedEncryptedData = Buffer.from(serverHello.encrypted, 'base64');

          const signature = cc.createSignatureByAlgorithm(serverHello.signatureAlgorithm) as cc.Signature;
          signature.init(serverPublicKey);
          signature.write(encodedProtectedData);
          signature.write(encodedEncryptedData);
          signature.end();
          if (!signature.verify(Buffer.from(serverHello.signature, 'base64'))) {
            return Promise.reject(new Error('packet verification failed'));
          }

          protectedData =
            JSON.parse(encodedProtectedData.toString('utf8'));

          const serverNonce = Buffer.from(protectedData.nonce, 'base64');
          connectionPrfHash = cc.createHash(protectedData.prfAlgo) as cc.Hash;

          const cipher = cc.createDecipher(protectedData.encAlgo);
          if (!cipher) {
            return Promise.reject(new Error('cipher algorithm not supported: ' + protectedData.encAlgo));
          }
          const remoteEphermalPublicKey =
            cc.createAsymmetricKey({
              format: 'der',
              key: Buffer.from(protectedData.ephemeralPublicKey, 'base64')
            });

          masterSecret = this._ephemeralPrivateKey.dhComputeSecret(remoteEphermalPublicKey);

          const handshakeSecret = this._deriveSecret({
            label: 'server-handshake',
            hash: connectionPrfHash,
            secret: masterSecret,
            serverNonce: serverNonce,
            clientNonce: this._clientNonce
          });
          const handshakeKeyIV = this._deriveKeyAndIV(handshakeSecret, cipher, {
            hash: connectionPrfHash,
            serverNonce: serverNonce,
            clientNonce: this._clientNonce
          });
          cipher.init({
            ...handshakeKeyIV
          });
          cipher.setAuthTag(Buffer.from(protectedData.authTag, 'base64'));
          const decrypted = safeBufferConcat([
            cipher.update(encodedEncryptedData),
            cipher.final()
          ]);
          const serverHelloEncrypted: payload.ServerHelloEncrypted = JSON.parse(decrypted.toString('utf8'));

          return opts.handshakeVerifier({
            serverHelloEncrypted: serverHelloEncrypted,
            serverCertificate: Object.freeze(serverHelloEncrypted.serverCertificate),
            extensions: serverHelloEncrypted.extensions,
            serverPublicKey: serverPublicKey
          })
            .then((verified) => {
              if (!verified) {
                return Promise.reject(new Error('server certificate verification failed'));
              }

              this._ephemeralPrivateKey = undefined as any;
              this._connectionEncAlgo = protectedData.encAlgo;
              this._connectionPrfHash = cc.createHash(protectedData.prfAlgo) as cc.Hash;
              this._connectionEncBase = cc.createCipher(protectedData.encAlgo) as cc.Cipher;
              this._masterSecret = masterSecret;
              this._serverNonce = Buffer.from(protectedData.nonce, 'base64');

              const wrappedTrafficSecret = this._deriveSecret({
                label: 'wrapped-traffic',
                seed: Buffer.from(serverHelloEncrypted.applicationTrafficSecretSalt, 'base64')
              });
              this._setApplicationTrafficSecret(wrappedTrafficSecret);

              this._handshakeState = HandshakeState.Handshaked;
              return this._wrapAndSend({
                $pt: payload.PayloadType.ClientFinishHandshake,
                message: 'OK'
              } as payload.ClientFinishHandshake)
                .then(() => {
                  if (opts.handshaked) {
                    opts.handshaked();
                  }
                });
            });
        } catch (e) {
          return Promise.reject(e);
        }
      });
  }

  public _clientFinishHandshakeProcess(payload: payload.TrafficKeyUpdate): Promise<void> {
    if (this._handshakeState !== HandshakeState.ServerHello) {
      return Promise.resolve();
    }

    this._handshakeState = HandshakeState.Handshaked;

    if (this._opts.handshaked) {
      this._opts.handshaked();
    }

    return Promise.resolve();
  }

  private _setApplicationTrafficSecret(secret: Buffer) {
    this._wrappedTrafficSecret = secret;
    this._wrappedTrafficKeyIV = this._deriveKeyAndIV(secret, this._connectionEncBase);
  }

  // private _trafficKeyUpdate() {
  //   const salt = crypto.randomBytes(32);
  //   const data: payload.TrafficKeyUpdate = {
  //     $pt: payload.PayloadType.TrafficKeyUpdate,
  //     salt: salt.toString('base64')
  //   };
  //   const newSecret = this._deriveSecret({
  //     label: 'wrapped-traffic',
  //     seed: salt,
  //     secret: this._wrappedTrafficSecret
  //   });
  //   const p = this._wrapAndSend(data);
  //   this._setApplicationTrafficSecret(newSecret);
  //   return p;
  // }

  private _wrapAndSend(data: payload.Payload): Promise<void> {
    const cipher = cc.createCipher(this._connectionEncAlgo) as cc.Cipher;
    cipher.init({
      ...this._wrappedTrafficKeyIV
    });
    const encrypted = safeBufferConcat([
      cipher.update(Buffer.from(JSON.stringify(data))),
      cipher.final()
    ]);
    const wrappedData: payload.WrappedData = {
      $pt: PayloadType.WrappedData,
      data: encrypted.toString('base64'),
      tag: cipher.getAuthTag().toString('base64')
    };
    return Promise.resolve(this._opts.send(wrappedData));
  }

  public _wrappedDataProcess(payload: payload.WrappedData): Promise<void> {
    try {
      const cipher = cc.createDecipher(this._connectionEncAlgo) as cc.Decipher;
      cipher.init({
        ...this._wrappedTrafficKeyIV
      });
      cipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
      const decrypted = safeBufferConcat([
        cipher.update(Buffer.from(payload.data, 'base64')),
        cipher.final()
      ]);
      const decryptedPayload: payload.Payload = JSON.parse(decrypted.toString('utf8'));
      if (availableWrappedPayloads.findIndex(v => v === decryptedPayload.$pt) < 0) {
        return Promise.reject(new Error('Unknown Payload: ' + decryptedPayload.$pt));
      }
      const handler = decryptedPayload.$pt && SimplePfsStream.payloadHandlers[decryptedPayload.$pt as payload.PayloadType];
      if (!handler) {
        return Promise.reject(new Error('Unknown Payload'));
      }
      return handler.call(this, decryptedPayload);
    } catch (e) {
      return Promise.reject(e);
    }
  }

  public _trafficKeyUpdateProcess(payload: payload.TrafficKeyUpdate): Promise<void> {
    return Promise.resolve();
  }

  // public _trafficKeyUpdateProcess(payload: payload.TrafficKeyUpdate): Promise<void> {
  //   const isHandshaked = this._opts.server && (this._handshakeState === HandshakeState.ServerHello);
  //   if (isHandshaked) {
  //     this._handshakeState = HandshakeState.Handshaked;
  //   }
  //   const newSecret = this._deriveSecret({
  //     label: 'wrapped-traffic',
  //     seed: Buffer.from(payload.salt, 'base64'),
  //     secret: this._wrappedTrafficSecret
  //   });
  //   this._setApplicationTrafficSecret(newSecret);
  //   if (isHandshaked) {
  //     this._opts.handshaked();
  //   }
  //   return Promise.resolve();
  // }

  public _applicationDataProcess(payload: payload.ApplicationData): Promise<void> {
    if (this._opts.dataReady) {
      this._opts.dataReady(payload.data);
    } else {
      this.push(payload.data);
    }
    return Promise.resolve();
  }

  _read(size: number) {
  }

  _write(chunk: any, encoding: BufferEncoding, callback: (error?: (Error | null)) => void) {
    this.send(chunk)
      .then(() => {
        callback();
      })
      .catch((err) => {
        callback(err);
      });
  }

  _final(callback: (error?: (Error | null)) => void) {
    if (this._handshakeState !== HandshakeState.Handshaked) {
      callback(new Error('Illegal state: not handshaked'));
      return ;
    }
    this._handshakeState = HandshakeState.Final;
    callback();
  }
}
