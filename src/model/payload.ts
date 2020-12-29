export namespace payload {

  export enum PayloadType {
    Alert = 'Alert',
    ClientHello = 'ClientHello',
    ServerHello = 'ServerHello',
    ClientFinishHandshake = 'ClientFinishHandshake',
    WrappedData = 'WrappedData',
    ApplicationData = 'ApplicationData',
    TrafficKeyUpdate = 'TrafficKeyUpdate',
  }

  export interface Payload {
    /**
     * Payload Type
     */
    $pt: string;
  }

  export type ErrorCode =
    'E_NOTIMPL' |
    'E_ILLEGAL_STATE' |
    'E_NOT_SUPPORTED_EPHEMERAL_ALGORITHM' |
    'E_NOT_SUPPORTED_ENCRYPT_ALGORITHM' |
    'E_NOT_SUPPORTED_PRF_ALGORITHM'
    ;

  export interface Alert extends Payload {
    $pt: PayloadType.Alert;
    code: ErrorCode;
    message: string;
  }

  export interface ClientHello extends Payload {
    $pt: PayloadType.ClientHello;

    /**
     * ephemeral key derivation algorithm
     */
    ephemeralAlgorithm: string;

    /**
     * Base64 encoded ephemeral client public key
     */
    ephemeralPublicKey: string;

    /**
     * availableEncryptionAlgorithms
     */
    availEncAlgo: string[];

    /**
     * availablePrfAlgorithms
     */
    availPrfAlgo: string[];

    /**
     * Base64 encoded clientNonce
     */
    nonce: string;
  }

  export interface ServerHelloEncrypted {
    /**
     * encoded base64 firstApplicationTrafficSecretSalt (32byte)
     */
    applicationTrafficSecretSalt: string

    /**
     * user-defined server certificate (metadata)
     */
    serverCertificate: any;

    /**
     * extensions
     */
    extensions?: any;
  }

  export interface ServerHelloProtected {
    /**
     * base64 encoded ephemeralServerPublicKey
     */
    ephemeralPublicKey: string;

    /**
     * negotiatedEncryptionAlgorithm
     */
    encAlgo: string;

    /**
     * negotiatedPrfAlgorithm
     */
    prfAlgo: string;

    /**
     * base64 encoded serverNonce
     */
    nonce: string;

    /**
     * base64 encoded encrypted data auth tag
     */
    authTag: string;
  }

  export interface ServerHello extends Payload {
    $pt: PayloadType.ServerHello;

    /**
     * signature algorithm oid
     */
    signatureAlgorithm: string;

    /**
     * Base64 encoded server public key
     */
    serverPublicKey: string;

    /**
     * base64 encoded plaintext json
     * See {@link ServerHelloProtected}
     */
    protected: string;

    /**
     * base64 encoded ciphertext json
     * See {@link ServerHelloEncrypted}
     */
    encrypted: string;

    /**
     * base64 encoded signature
     */
    signature: string;
  }

  export interface ClientFinishHandshake extends Payload {
    $pt: PayloadType.ClientFinishHandshake;
    message: 'OK';
  }

  export interface WrappedData extends Payload {
    $pt: PayloadType.WrappedData;

    /**
     * Base64 encoded encrypted payload
     */
    data: string;

    /**
     * Base64 encoded auth tag
     */
    tag: string;
  }

  export interface ApplicationData extends Payload {
    $pt: PayloadType.ApplicationData;
    data: any;
  }

  export interface TrafficKeyUpdate extends Payload {
    $pt: PayloadType.TrafficKeyUpdate;
    salt: string;
  }

  export interface TrafficKeyUpdate extends Payload {
    $pt: PayloadType.TrafficKeyUpdate;
    salt: string;
  }
}

export default payload;
