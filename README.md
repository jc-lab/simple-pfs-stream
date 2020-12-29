# simple-pfs-stream

JSON-based perfect forward secrecy stream

# Handshake Process

## Functions

### DeriveSecret\(masterKey, label\[, seed\]\)

= HKDF(algo=*connectionHashAlgo*, secret=*masterKey*, message=*label* + *clientNonce* + *serverNonce* + *seed*)

### JSON-Base64

* Encoding = Base64Encode(JSON_Stringify(input))
* Decoding = JSON_Parse(Base64Decode(input))

## Step 1. ClientHello

* Direction : Client -> Server

### Payload

 - ephemeralAlgorithm
 - ephemeralClientPublicKey
 - availableEncryptionAlgorithms \(Array order is priority\)
 - availablePrfAlgorithms \(Array order is priority\)
 - available
 - clientNonce

## Step 2. ServerHello

* Direction : Server -> Client

### Internal Values

- masterSecret = ECDH(ephemeralServerPrivateKey, ephemeralClientPublicKey)
- serverHandshakeKey = DeriveSecret(masterSecret, "server-handshake")
- (initial) wrappedTrafficSecretKey = DeriveSecret(masterSecret, "wrapped-traffic-key", firstWrappedTrafficSecretSalt)
- (initial) wrappedTrafficSecretIV = DeriveSecret(masterSecret, "wrapped-traffic-iv", firstWrappedTrafficSecretSalt)

### Payload

 - signatureAlgorithm
 - serverPublicKey
 - protected : JSON-Base64 Encoded String
   - ephemeralServerPublicKey
   - negotiatedEncryptionAlgorithm
   - negotiatedPrfAlgorithm
   - serverNonce
 - encrypted : (= Encrypt(serverHandshakeKey, ...))
   - serverCertificate (User defined metadata)
   - firstWrappedTrafficSecretSalt
   - extensions
 - payloadSignature (= SIGN(serverPublicKey, \[protectedHeader, protectedData\]))

## Step 3. Finish

* Direction : Client -> Server

### Internal Values

- masterSecret = ECDH(ephemeralClientPrivateKey, ephemeralServerPublicKey)
- serverHandshakeKey = DeriveSecret(masterSecret, "server-handshake")
- (initial) wrappedTrafficSecretKey = DeriveSecret(masterSecret, "wrapped-traffic-key", firstWrappedTrafficSecretSalt)
- (initial) wrappedTrafficSecretIV = DeriveSecret(masterSecret, "wrapped-traffic-iv", firstWrappedTrafficSecretSalt)

### Payload

...

## TODO: TrafficKeyUpdate

* Direction : Anyone -> Other
* Wrapping Key = wrappedTrafficSecret

### Payload

- seed = random 32byte

### After

wrappedTrafficSecret = DeriveSecret(wrappedTrafficSecret, "application-traffic", seed)

## Wrapped Data

### From Server

* Direction : Server -> Client
* Key = application_traffic_secret

### From Server

* Direction : Client -> Server
* Key = client_application_traffic_secret
