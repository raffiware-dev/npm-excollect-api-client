/*
 *  ExCollect API Crypt Utility Types and Functions. 
 *
 */
import { getCurrentTimeStamp, uuidBufToUuid } from './utils.js';
import type { 
  CommandInstance, 
  ExcRequestConfig, 
  ExcSignOpts
} from '../excollect-client.js';
import base64url from "base64url";
import type { Base64Url } from "base64url";
import { sha256 } from 'js-sha256'
import { Buffer } from 'buffer';
import ece from 'http_ece';
import { encodings, encrypt, decrypt } from '@apeleghq/rfc8188';

type Tokens = {
  [key: string] : string | number | Uint8Array 
}

export interface PubKeyData {
  id:          string;
  owner_id:    string;
  created:     string;
  expires:     string;
  public_key:  string;
  context?:    Tokens & { api: string };
  signed_by?:  PubKeyData | string;
  signature?:  string
}

export interface EncryptedKeyData extends PubKeyData {
  key_data:   string;
}

const IV_BIT_LENGTH         = 96;
const AES_GCM_KEY_LENGTH    = 128;
const SECRET_KEY_BIT_LENGTH = 256;

const SUBTLE = crypto.subtle;

/**
 * 
 * @returns {CryptoKeyPair} - Ed25519 Keys.
 */
export async function createEd25519Keys() {

  return SUBTLE.generateKey(
    {
      name: "Ed25519",
    },
    true,
    ["sign", "verify"],
  );
}

/**
 * 
 * @returns {CryptoKeyPair}  - X25519 Keys.
 */
export async function createX25519Keys() {

  return SUBTLE.generateKey(
    {
      name: "X25519",
    },
    true,
    ["deriveKey", "deriveBits"],
  );
}

/**
 * @param {CryptoKey}  pk     X25519 CryptoKey containing private key.
 * @param {CryptoKey}  pubPk  X25519 CryptoKey containing public key.
 * 
 * @returns {ArrayBuffer} .
 */
export async function deriveSecret( 
  pk:    CryptoKey, 
  pubPk: CryptoKey,
) {

  return SUBTLE.deriveBits(
    {
      name: "X25519",
      public: pubPk,
    },
    pk,
    SECRET_KEY_BIT_LENGTH
  );
}

/**
 * RFC8188 encryption function using http_ece.
 * 
 * @deprecated 
 * 
 * @param {string}  data  Data to be encrypted
 * @param {secret}  ArrayBuffer  secret key
 * 
 * @returns {string} Base64Url encoded cipher.
 */
export async function eceEncrypt( 
  data:   string, 
  secret: ArrayBuffer 
) {

  const dataBuf = Buffer.from(data);

  /* X25519 produces 256 bit shared secrets but ece.encrypt()
     takes a 128 bit key for aes128gcm so we run the original 
     secret through HKDF to derive properly sized and 
     randomized IKM. 
  */
  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    secret,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const salt = crypto.getRandomValues(new Uint8Array(16));

  const derivedSecret = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: Buffer.from(''),
      info: buildInfoBuf("Content-Encoding: aes128gcm")
    }, 
    sharedSecretKey,
    AES_GCM_KEY_LENGTH
  );

  const parameters = {
    //key:  bufToBase64URL(derivedSecret),
    key:  Buffer.from(derivedSecret),
    salt: salt
  };

  return bufToBase64URL(ece.encrypt( dataBuf, parameters ));
}

/**
 * RFC8188 decryption function.
 * 
 * @deprecated 
 * 
 * @param {string}  cipher  Base64Url encoded cipher
 * @param {string}  secret  Base64Url encoded secret key.
 * 
 * @returns {string} plain text
 */
export async function eceDecrypt( 
  cipher: string, 
  secret: string 
) {

  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    base64URLToBuf(secret),
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const derivedSecret = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: Buffer.from(''),
      info: buildInfoBuf("Content-Encoding: aes128gcm")
    }, 
    sharedSecretKey,
    AES_GCM_KEY_LENGTH
  );

  const parameters = {
    //key: bufToBase64URL(derivedSecret),
    key: Buffer.from(derivedSecret)
  };

  // http_ece needs buf to really be a Buffer
  // and breaks with an ArrayBuffer
  const cipherBuf = Buffer.from(base64URLToBuf(cipher));

  return ece.decrypt( cipherBuf, parameters );
}

/**
 * RFC8188 encryption function using @apeleghq/rfc8188.
 * 
 * @param {string}  data  Data to be encrypted
 * @param {secret}  ArrayBuffer  secret key
 * 
 * @returns {string} Base64Url encoded cipher.
 */
export async function eceEncrypt2( 
  data:   string, 
  secret: ArrayBuffer 
) {

  const dataBuf = Buffer.from(data);
  const salt    = crypto.getRandomValues(new Uint8Array(16));

  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    secret,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const derivedSecret = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: Buffer.from(''),
      info: buildInfoBuf("Content-Encoding: aes128gcm")
    }, 
    sharedSecretKey,
    AES_GCM_KEY_LENGTH
  );

  const dataStreamToEncrypt = bufferToStream(dataBuf);

  const keyId      = new ArrayBuffer(0);
  const recordSize = 512;
  const encryptedDataStream = await encrypt(
      encodings.aes128gcm,
      dataStreamToEncrypt,
      recordSize,
      keyId,
      derivedSecret,
      salt
  );

  const result = await streamToBuf(encryptedDataStream);

  return bufToBase64URL(result);
}

/**
 * RFC8188 decryption function.
 * 
 * @param {string}  cipher  Base64Url encoded cipher
 * @param {string}  secret  Base64Url encoded secret key.
 * 
 * @returns {string} plain text
 */
export async function eceDecrypt2( 
  cipher: string, 
  secret: ArrayBuffer 
) {

  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    secret,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const derivedSecret = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: Buffer.from(''),
      info: buildInfoBuf("Content-Encoding: aes128gcm")
    }, 
    sharedSecretKey,
    AES_GCM_KEY_LENGTH
  );

  const cipherBuf           = Buffer.from(base64URLToBuf(cipher));
  const dataStreamToDecrypt = bufferToStream(cipherBuf);

  const decryptedDataSteam = decrypt(
      encodings.aes128gcm,
      dataStreamToDecrypt,
      async () => { return Buffer.from(derivedSecret) },
  );

  const result = await streamToBuf(decryptedDataSteam);

  return result.toString()
}

async function streamToBuf( s: ReadableStream<ArrayBufferLike|BufferSource> ) {

  const result = await new Response( ArrayBufferToUint8ArrayStream(s) ).arrayBuffer();

  return Buffer.from(result)
}

/* Borrowed from @apeleghq/rfc8188 tests */
const ArrayBufferToUint8ArrayStream = (s: ReadableStream<ArrayBufferLike|BufferSource>) =>
	s.pipeThrough(
		new TransformStream<ArrayBufferLike, Uint8Array>({
			start() {},
			transform(chunk, controller) {
				if (ArrayBuffer.isView(chunk)) {
					controller.enqueue(
						new Uint8Array(
							chunk.buffer,
							chunk.byteOffset,
							chunk.byteLength,
						),
					);
				} else {
					controller.enqueue(new Uint8Array(chunk));
				}
			},
		}),
	);

function bufferToStream(buf: Uint8Array) {
	let pos = 0;
	return new ReadableStream({
		pull(controller) {
			if (pos === buf.byteLength) {
				controller.close();
				return;
			}
			const chunkSize =
				1 + (((0, Math.random)() * (buf.byteLength - pos)) | 0);
			controller.enqueue(buf.subarray(pos, pos + chunkSize));
			pos += chunkSize;
		},
	});
}

/**
 * AES-GCM encryption function that encodes the 
 * salt, cipher and tag. Similar to and will 
 * probably be replaced by the RFC8188 functions.
 * 
 * @param {string}       data  Data to be encrypted
 * @param {ArrayBuffer}  ArrayBuffer  Symetric Key
 * 
 * @returns {string} Base64Url encoded cipher.
 */
export async function encryptWithSecret( 
  data:   string, 
  secret: ArrayBuffer 
) {

  const salt    = crypto.getRandomValues(new Uint8Array(32) );
  const enc     = new TextEncoder();
  const encoded = enc.encode(data); 

  const { ivBuf, derivedKey } = await buildAesIvKey( secret, salt );

  const cipherTag = await SUBTLE.encrypt(
    { name: "AES-GCM", 
      iv:   ivBuf 
    }, 
    derivedKey, 
    encoded 
  );

  const saltCipherTag = new Uint8Array( 32 + cipherTag.byteLength );
  const cipherTagView = new Uint8Array( cipherTag );

  saltCipherTag.set( salt, 0 );
  saltCipherTag.set( cipherTagView, 32 ); 

  return saltCipherTag;
}

/**
 * Decrypts data encrypted with encryptWithSecret()  
 * implementation.
 * 
 * @param {Uint8Array}   saltCipherTag  Encoded cipher
 * @param {ArrayBuffer}  secret         Symmetric key 
 * 
 * @returns {string} plain text
 */
export async function decryptWithSecret( 
  saltCipherTag: Uint8Array, 
  secret:        ArrayBuffer 
) { 

  const dec       = new TextDecoder();
  const salt      = saltCipherTag.slice( 0, 32 );
  const cipherTag = saltCipherTag.slice( 32, saltCipherTag.length );

  const { ivBuf, derivedKey } = await buildAesIvKey( secret, salt );

  const unEncrypted = await SUBTLE.decrypt(
    { name: "AES-GCM",  
      iv:   ivBuf 
    },
    derivedKey,
    cipherTag
  );

  return dec.decode(unEncrypted);
}

async function buildAesIvKey( 
  secret: ArrayBuffer, 
  salt:   Uint8Array<ArrayBuffer> 
) {

  const keySalt = salt.slice(0, 16);
  const ivSalt  = salt.slice(16, 32);

  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    secret,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"]
  );

  const derivedKey = await SUBTLE.deriveKey(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: keySalt, 
      info: buildInfoBuf("Content-Encoding: aes128gcm")
    }, 
    sharedSecretKey, 
    { name:   "AES-GCM", 
      length: 128 
    },
    true,
    ["encrypt", "decrypt"]
  );

  const derivedIv = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: ivSalt, 
      info: buildInfoBuf("Content-Encoding: nonce")
    }, 
    sharedSecretKey,
    IV_BIT_LENGTH 
  );

  const ivBuf = new Uint8Array(derivedIv);

  return { ivBuf, derivedKey };
}

function buildInfoBuf(
  infoText: string 
) {

  const enc     = new TextEncoder(); 
  const textBuf = enc.encode(infoText);
  const infoBuf = new Uint8Array(textBuf.length + 1 );

  infoBuf.set( textBuf, 0 );
  infoBuf.set( [0x00], textBuf.length ); 

  return infoBuf;
}

/**
 * @param {CryptoKey}  pk          ED25519 CryptoKey containing private key.
 * @param {CryptoKey}  loginPubPk  X25519 CryptoKey containing public key.
 * @param {string}     keyId       Key Id
 * 
 * @returns {string} Encoded and encrypted pk private key .
 */
export async function lockApiKey(
  pk:         CryptoKey,
  loginPubPk: CryptoKey,
  keyId:      string
) {

   const idBuf     = idToUuidBuf(keyId);
   const salt      = crypto.getRandomValues(new Uint8Array(32));
   const keyBuffer = await encryptKeyV1( pk, loginPubPk, idBuf, salt );

   return bufToBase64URL(keyBuffer);
}

/**
 * @param {string}     keyData     encrypted ED25519  private key.
 * @param {CryptoKey}  loginPubPk  X25519 CryptoKey containing private key.
 * @param {string}     keyId       Key Id
 * 
 * @returns {CryptoKey, string} ED25519 key and base64url encoding private key. 
 */

export async function unlockApiKey(
  keyData:     string,
  loginPrivPk: CryptoKey,
  keyId:       string
) {

   const idBuf      = idToUuidBuf(keyId);
   const keyDataBuf = getEncStrBuffer(keyData);

   const unEncryptedBuf = await decryptKeyV1( keyDataBuf, loginPrivPk, idBuf );
   const apiPrivEnc     = bufToBase64URL(unEncryptedBuf);

   const apiPrivPk = await SUBTLE.importKey(
     "pkcs8",
     unEncryptedBuf,
     'Ed25519', 
     true,
     ['sign'] 
   );

   return { apiPrivPk, apiPrivEnc }
}

/**
 *
 * @param {string}   keyData     encrypted ED25519  private key.
 * @param {string}   passPhrase  passphrase.
 * @param {string}   keyId       Key Id
 * 
 * @returns {CryptoKey, string} ED25519 key and base64url encoding private key. 
 */
export async function unlockLoginKey(
  keyData:    string,
  passphrase: string,
  keyId:      string
) {

   const idBuf           = idToUuidBuf(keyId);
   const keyDataBuf      = getEncStrBuffer(keyData);
   const passphraseSalt  = Buffer.from(keyDataBuf.slice(33, 65)).reverse().buffer;

   const passphrasePk = await passphraseToX25519( passphrase, passphraseSalt, idBuf );
   const loginKeyBuf  = await decryptKeyV1( keyDataBuf, passphrasePk, idBuf );
   const loginPrivEnc = bufToBase64URL(loginKeyBuf);

   const loginPrivPk = await SUBTLE.importKey(
     "pkcs8",
     loginKeyBuf,
     'x25519', 
     true,
     ['deriveKey', 'deriveBits'] 
   );

   return { loginPrivPk, loginPrivEnc }
}
/**
 * Derive a X225519 Key from a passphrase
 * 
 * @param {string}       passPhrase
 * @param {ArrayBuffer}  salt 
 * @param {Uint&Array}   idBuf 
 * 
 * @returns {CryptoKey} X25519 key . 
 */
export async function passphraseToX25519(
  passphrase: string,
  salt:       ArrayBuffer,
  idBuf:      Uint8Array
) {

   const passphraseKey = await SUBTLE.importKey(
     "raw",
     new Uint8Array( str2ab( passphrase ) ),
     { name: "HKDF" },
     false,
     ["deriveBits"]
   );

   const derivedKmBuf = await SUBTLE.deriveBits(
     { name: "HKDF", 
       hash: "SHA-256", 
       salt: salt, 
       info: buildInfoIdBuf("Content-Encoding: passphrase", idBuf )
     }, 
     passphraseKey, 
     SECRET_KEY_BIT_LENGTH
   );

   const derivedPrivateKeyData = new Uint8Array(derivedKmBuf);

   /* Although Web Crypto appears to also clamp the private key 
      on import we still explicity do this so that keys generated
      here can be used in other implementations of the algorithm.
   */
   let msb = derivedPrivateKeyData.at(0)  as number;
   let lsb = derivedPrivateKeyData.at(31) as number;

   msb &= 248;
   lsb &= 127;
   lsb |= 64;
   derivedPrivateKeyData.set( [msb], 0 )
   derivedPrivateKeyData.set( [lsb], 31 )

   /* Raw private keys cannot be directly imported so we have to 
      construct a pksc8 formatted key by prepending the ASN1 encoded 
      data for a X25519 key. 

      pksc8Data will decode as:

      U.P.SEQUENCE {
         U.P.INTEGER 0x00 (0 decimal)         # Version
         U.P.SEQUENCE {
            U.P.OBJECTIDENTIFIER 1.3.101.110  # X25519 Algorithm OID -> http://www.oid-info.com/get/1.3.101.110
         }
         U.P.OCTETSTRING                      # ASN.1 tag for an OCTET STRING ( 04 ), Key Length ( 32 ), Key Data 
            U.P.OCTETSTRING                   # Key Data
      
      }

   */
   const pksc8X25519Prefix = new Uint8Array(hex2buf('302e020100300506032b656e04220420'));
   const pksc8Data         = new Uint8Array(48);
   pksc8Data.set( pksc8X25519Prefix, 0 )
   pksc8Data.set( derivedPrivateKeyData, 16 )

   return SUBTLE.importKey(
     'pkcs8',
     pksc8Data,
     'x25519', 
     true,
     ["deriveBits"]
   );
}

/**
 * Encrypts a private key with a shared secret derived from a 
 * provided X25519 public key and a generated ephemeral X25519 key.
 *
 * The cipher text is returned with the data necessary to 
 * decrypt the private key using X25519 private key that matches
 * the provided public key.
 * 
 * @param {CryptoKey}    pk        Key to be encrypted 
 * @param {CryptoKey}    lockPubPk Public key used for derived shared secret  
 * @param {Uint&Array}   idBuf     Shared Secret HKDF info 
 * @param {Uint&Array}   salt      32 byte random salt.
 * 
 * @returns {Uint8Array} 
 * 
 *          Byte Offset | Byte Length | Value 
 *          0           |           1 | Version number
 *          1           |          32 | Generated X25519 Pub Key     
 *          33          |          32 | Random Salt 
 *          65          |          48 | PKSC8 Private KeyCipher 
 *          114         |          16 | AES-GCM Tag 
*/
async function encryptKeyV1(
  pk:        CryptoKey,
  lockPubPk: CryptoKey,
  idBuf:     Uint8Array,
  salt:      Uint8Array<ArrayBuffer>
) {

  const { privateKey, publicKey } = await createX25519Keys() as CryptoKeyPair;

  const pubDhKeyData  = await SUBTLE.exportKey("raw", publicKey );
  const encryptingKey = await exportKey(pk);
  const secret        = await deriveSecret( privateKey, lockPubPk );

  const keySalt = salt.slice(0,16);
  const ivSalt  = salt.slice(16,33);

  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    secret,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"]
  );

  const derivedKey = await SUBTLE.deriveKey(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: keySalt, 
      info: buildInfoIdBuf("Content-Encoding: aes128gcm", idBuf )
    }, 
    sharedSecretKey, 
    { name:   "AES-GCM", 
      length: 128 
    },
    true,
    ["encrypt"]
  );

  const derivedIv = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: ivSalt, 
      info: buildInfoIdBuf("Content-Encoding: nonce", idBuf)
    }, 
    sharedSecretKey,
    IV_BIT_LENGTH 
  );

  const ivBuf = new Uint8Array(derivedIv);

  const cipherTag = await SUBTLE.encrypt(
    { name: "AES-GCM", 
      iv:   ivBuf 
    }, 
    derivedKey, 
    encryptingKey as ArrayBuffer
  );

  const versionView    = new Uint8Array([1]);
  const dhKeyView      = new Uint8Array(pubDhKeyData); 
  const cipherTagView  = new Uint8Array(cipherTag);
  const encodedKeydata = new Uint8Array( 
                           versionView.byteLength 
                           + dhKeyView.byteLength 
                           + salt.byteLength 
                           + cipherTag.byteLength 
                         );

  encodedKeydata.set( versionView, 0 );
  encodedKeydata.set( dhKeyView, versionView.byteLength );
  encodedKeydata.set( salt, versionView.byteLength + dhKeyView.byteLength );
  encodedKeydata.set( cipherTagView, 
                   versionView.byteLength 
                   + dhKeyView.byteLength 
                   + salt.byteLength 
                 );

  return encodedKeydata;
}
/**
 * @param {ArrayBuffer}  keyDataBuf   Encrypted key data returned from encryptKeyV1()
 * @param {CryptoKey}    lockPubPk    Private key used for derived shared secret  
 * @param {Uint&Array}   idBuf        Shared Secret HKDF info 
 */
async function decryptKeyV1(
  keyDataBuf: ArrayBuffer,
  lockPrivPk: CryptoKey,
  idBuf:      Uint8Array 
) {

  checkKeyDataVersion( keyDataBuf, 1 )

  /* TODO create getKeyDataBuf() data */
  const dhKeyPub  = new Uint8Array(keyDataBuf.slice(1,33));
  const salt      = keyDataBuf.slice(33, 65);
  const cipherTag = new Uint8Array(keyDataBuf.slice( 65, keyDataBuf.byteLength ));

  const pubPk = await SUBTLE.importKey(
    "raw",
    dhKeyPub,
    'x25519', 
    true,
    []
  );

  const secret  = await deriveSecret( lockPrivPk, pubPk );
  const keySalt = salt.slice(0,16);
  const ivSalt  = salt.slice(16,33);

  const sharedSecretKey = await SUBTLE.importKey(
    "raw",
    secret,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"]
  );

  const derivedKey = await SUBTLE.deriveKey(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: keySalt, 
      info: buildInfoIdBuf("Content-Encoding: aes128gcm", idBuf )
    }, 
    sharedSecretKey, 
    { name:   "AES-GCM", 
      length: 128 
    },
    true,
    ["decrypt"]
  );

  const derivedIv = await SUBTLE.deriveBits(
    { name: "HKDF", 
      hash: "SHA-256", 
      salt: ivSalt, 
      info: buildInfoIdBuf("Content-Encoding: nonce", idBuf)
    }, 
    sharedSecretKey,
    IV_BIT_LENGTH 
  );

  const ivBuf = new Uint8Array(derivedIv);

  const unEncrypted = await SUBTLE.decrypt(
    { name: "AES-GCM",  
      iv:   ivBuf 
    },
    derivedKey,
    cipherTag
  );

  return unEncrypted;
}

function buildInfoIdBuf(
  infoText: string,
  idBuf:    Uint8Array
) {

  const baseBuf = buildInfoBuf(infoText);
  const infoBuf = new Uint8Array( baseBuf.length + idBuf.length + 1 );

  infoBuf.set( baseBuf, 0 );
  infoBuf.set( idBuf, baseBuf.length );
  infoBuf.set( [0x00], baseBuf.length + idBuf.length );

  return infoBuf;
}

function checkKeyDataVersion(
  keyDataBuf:     ArrayBuffer,
  keyDataVersion: number
) {

  const version = new Uint8Array(keyDataBuf.slice(0,1))[0];
 
  if ( version !== keyDataVersion ) {
    throw new Error('Incorrect key version');
  }
}

function idToUuidBuf( 
   id: string
) {
  const idHex = id.substring( id.indexOf('_') + 1 );

  return new Uint8Array(hex2buf(idHex));
}

export async function signApiRequest( 
  reqCfg: ExcRequestConfig, 
  opts:   ExcSignOpts 
) {

  const tokens = getTokensForRequest( reqCfg, opts );

  reqCfg.headers ||= {};

  reqCfg.headers['X-EXC-KeyID']      = tokens['KeyID'];
  reqCfg.headers['X-EXC-Nonce']      = tokens['Nonce'];
  reqCfg.headers['X-EXC-TimeOffset'] = tokens['TimeOffset'];
  reqCfg.headers['X-EXC-TimeStamp']  = tokens['TimeStamp'];
  reqCfg.headers['X-EXC-Signature']  = await signTokens( tokens, opts['pk'] );

  return reqCfg;
}

function getTokensForRequest( 
  reqCfg: ExcRequestConfig, 
  opts:   ExcSignOpts 
) {

  const url    = new URL( reqCfg.baseURL as string + reqCfg.url as string );
  /* query_string in request path must be URI encoded before signing. */
  const method = reqCfg.method?.toLowerCase() as string;

  /* Axios unescapes ':' so we have to unescape it for our 
   * token value too so everything matches up on the server.
   * See: axios/lib/helpers/buildURL.js */
  const query_string = new URLSearchParams(reqCfg.params)
                         .toString()
                         .replace(/%3A/gi, ':')
                         .replace(/,/gi, '%2C');


  const request_path    = url.pathname + ( query_string ? '?'+  query_string : '' );
  const request_content = reqCfg.data === undefined 
                          ? '' 
                          : reqCfg.data; 

  const hashed_content = sha256.create()
                           .update( request_content )
                           .hex(); 

  const tokens = {
    'Content'      : hashed_content,
    'KeyID'        : opts['keyId'],
    'Nonce'        : generateNonce(),
    'RequestMethod': method,
    'Resource'     : reqCfg.baseURL as string,
    'ResourcePath' : request_path,
    'TimeOffset'   : opts['timeOffset'],
    'TimeStamp'    : getCurrentTimeStamp()
  };

  return tokens; 
}

export async function signPublicKey( 
  keyData:  PubKeyData, 
  signerPk: CryptoKey 
) {

  const pKey   = keyData['public_key'];
  const keyBuf = new Uint8Array( getEncStrBuffer(pKey) );

  const tokens: PubKeyTokens = {
    "id":       keyData['id'],
    "owner_id": keyData['owner_id'],
    "created":  keyData['created'],
    "expires":  keyData['expires'],
    "pub_key":  keyBuf
  };

  if ( keyData["context"] !== undefined ) {
    tokens["context"] = generateMsgFromTokens( keyData["context"] as Tokens );
  }

  return signTokens( tokens, signerPk ); 
}

export async function verifyPublicKeyAndSigner( 
  keyData:     PubKeyData, 
  authorityPk: CryptoKey 
) {

  const signerKeyData = keyData['signed_by'] as PubKeyData; 

  if ( !await verifyPublicKey( signerKeyData, authorityPk ) ) {
    throw new Error('Signer Key did not verify');
  }

  const signerPubKey = signerKeyData['public_key'];
  const signerPubPk  = await loadPublicKey(signerPubKey);

  return verifyPublicKey( keyData, signerPubPk );
}

type PubKeyTokens = {
  id:       string;
  owner_id:  string;
  created:  string;
  expires:  string;
  pub_key:  Uint8Array;
  context?: Uint8Array
}

export async function verifyPublicKey( 
  keyData:     PubKeyData, 
  authorityPk: CryptoKey 
) {

  const sig    = keyData['signature'] as string; 
  const pKey   = keyData['public_key'];
  const keyBuf = new Uint8Array( getEncStrBuffer(pKey) );

  const tokens: PubKeyTokens = {
    "id":       keyData['id'],
    "owner_id": keyData['owner_id'],
    "created":  keyData['created'],
    "expires":  keyData['expires'],
    "pub_key":  keyBuf
  };

  if ( keyData["context"] !== undefined ) {
     tokens["context"] = generateMsgFromTokens( keyData["context"] as Tokens );
  }

  return verifyTokens(tokens, sig, authorityPk); 
}

export async function signCommandInstance( 
  commandInstance: CommandInstance,
  keyId:           string,
  pk:              CryptoKey
) {

  const tokens = {
    instance_id:    commandInstance['id'],
    command_id:     commandInstance['command'], 
    site_id:        commandInstance['site'],
    site_user_id:   commandInstance['signed_by'], 
    created_ts:     commandInstance['created_datetime'],
    key_id:         keyId,
    command_string: commandInstance['command_string'],
  };

  if ( commandInstance['execute_type'] == 'script' ) {
    const src_hash = sha256.create()
                       .update( commandInstance['script_src'] )
                       .hex();

    tokens['command_string'] = tokens['command_string'] + src_hash;
  }
  const signature = await signTokens( tokens, pk );

  const jobSigings = commandInstance.client_jobs?.map( 
     (job) => {

        const jobTokens = {
          job_id:       job.id,
          client_id:    job.client.id,
          instance_sig: signature 
        }

        return signTokens( jobTokens, pk )
                 .then((signature) => { return [ job.id, signature ]});
     }
  )

  const jobSigs = Object.fromEntries( await Promise.all(jobSigings) );

  return { signature, keyId, jobSigs };
}

export async function createSignedDhKey( 
  excPk:     CryptoKey
) {

  const { publicKey, privateKey } = await createX25519Keys() as CryptoKeyPair;

  const dhPub = await exportKey(publicKey) as ArrayBuffer;

  const signature = await SUBTLE.sign(
    "Ed25519",
    excPk,
    dhPub 
  );

  const sigEnc   = bufToBase64URL( signature );
  const dhPubEnc = bufToBase64URL( dhPub );

  return { dhPubEnc, sigEnc, privateKey }
}

export async function verifySignedDhKey( 
  dhPubEnc:  string,
  signature: string,
  pubPk:  CryptoKey
) {

  const keyBuf = new Uint8Array(base64URLToBuf(dhPubEnc));

  return SUBTLE.verify(
    "Ed25519",
    pubPk,
    base64URLToBuf(signature),
    keyBuf,
  );
}

export async function createKeyChangeAuthorization( 
  authorizorId: string,
  authorizorPk: CryptoKey,
  userUuid:     string,
  context:      string,
  contextId:    string,
  privileged:   number = 0,
  updates:      { status? : string } = {},
) {

  const authorizorUuid = uuidBufToUuid( idToUuidBuf(authorizorId) );
  const date_ts        = getCurrentTimeStamp();

  const tokens = {
     [context]:    uuidBufToUuid( idToUuidBuf(contextId) ),
     'user':       userUuid,
     'privileged': privileged,
     'date_ts':    date_ts,
     ...( updates['status'] && { status: updates['status'] })
  };

  if (  updates['status'] !== undefined ) {
     tokens['status'] = updates['status']
  }

  return {
    'signature':          await signTokens( tokens, authorizorPk ),
    'signature_ts':       date_ts,
    'authorized_by_uuid': authorizorUuid,
    'privileged':         privileged,
    'context_id':         contextId,
    ...( updates['status'] && { status: updates['status'] })
  };
}

export function generateNonce() {

  const array = new Uint32Array(1);

  array[0] = 0;
  crypto.getRandomValues(array);

  const randomNumber = array[0] / (0xffffffff + 1);

  /* Roughly all possible U32bit 10 digit numbers */
  const min = 0x40000000;
  const max = 0xffffffff;

  return Math.floor( randomNumber * (max - min + 1)) + min;
}

export async function signTokens( 
  tokens: Tokens, 
  pk:     CryptoKey 
) {

  const msg = generateMsgFromTokens(tokens);

  const signature = await SUBTLE.sign(
    "Ed25519",
    pk,
    msg
  );

  return bufToBase64URL( signature );
}

export async function verifyTokens(
  tokens: Tokens,
  sig:    string,
  pk:     CryptoKey 
) {

  const msg = generateMsgFromTokens(tokens);

  return SUBTLE.verify(
    "Ed25519",
    pk,
    base64URLToBuf(sig),
    msg,
  );
}

export function generateMsgFromTokens(
  tokens: Tokens
) {

  const enc       = new TextEncoder();
  const tokenKeys = Object.keys(tokens);
  const comma_enc = enc.encode(',');

  const allValues: Array<Uint8Array> = [];

  tokenKeys.sort().map( (t,i) => {
     const tVal = tokens[t];

     /* Don't put already encoded binary data through 
      * a utf-8 text encoder */
     if ( tVal instanceof Uint8Array && tVal.length > 0 )  {
       allValues.push( tVal as Uint8Array )
     } 
     else if ( tVal !== undefined || tVal !== '' ) {
       allValues.push( enc.encode( tVal as string ) )
     }
     else {
       return
     }

     /* Sorted values are joined on commas */
     if ( i < tokenKeys.length - 1 ) {
       allValues.push( comma_enc )
     }
  });

  /* Flatten all our Uint8Array's into one */
  let length = 0;
  allValues.forEach(item => {
    length += item.length;
  });

  const mergedArray = new Uint8Array(length);
  let offset      = 0;

  allValues.forEach(item => {
    mergedArray.set(item, offset);
    offset += item.length;
  });

  return mergedArray;
} 

export async function loadPrivateKey( 
  privKey:   string, 
  algorithm: string          = "Ed25519", 
  format:    "pkcs8" | "raw" = 'pkcs8'
) {

  const keyBuf = getEncStrBuffer(privKey);

  const pk = await SUBTLE.importKey(
    format,
    keyBuf,
    algorithm, 
    true,
    ( algorithm.toLowerCase() === "ed25519" ) ? ['sign'] :
    ( algorithm.toLowerCase() === "x25519" )  ? ["deriveKey", "deriveBits"] :
    []
  );

  return pk;
}

export async function loadPublicKey(
  pubKey:    string,
  algorithm: string = "Ed25519"
) {

  const keyBuf = getEncStrBuffer(pubKey);
  const pk = await SUBTLE.importKey(
    "spki",
    keyBuf,
    algorithm,
    true,
    ( algorithm.toLowerCase() === "ed25519" ) ? ['verify'] :
    ( algorithm.toLowerCase() === "x25519" )  ? [] : 
    [],
  );

  return pk;
}

async function exportKey( 
  key: CryptoKey 
) {

  if (!key.extractable) {
    throw new Error('Key is not extractable'); 
  }

  const type = key.type;

  if ( type === 'private' ) { 
     return SUBTLE.exportKey("pkcs8", key);
  }
  else if ( type === 'public' ) { 
     return SUBTLE.exportKey("spki", key);
  }

  return undefined
}

async function exportKeyEncoded( 
    key: CryptoKey 
) {
  const exportedKey = await exportKey( key ) as ArrayBuffer;

  return bufToBase64URL(exportedKey);
}

function getEncStrBuffer(
  encKey: string
) {

  const decoder = base64url.default as Base64Url;
  const pKeyDer = decoder.decode(encKey, 'binary');

  return str2ab(pKeyDer);
}

function str2ab(
  str: string 
) {

  const buf     = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);

  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

function hex2buf( 
  str: string 
) {
  return Buffer.from(str, 'hex') 
}

function bufToBase64URL(
  buf: Uint8Array<ArrayBuffer> | ArrayBuffer
) {

  const encoder = base64url.default as Base64Url;

  return encoder.encode(buf, 'binary'); 
}

function base64URLToBuf(
  str: string 
) {

  const encoder = base64url.default as Base64Url;

  return str2ab(encoder.decode(str, 'binary')); 
}

export class Encryptor {

  public  keyId: string; // theirDh keyID

  private ourPrivKey!: CryptoKey;
  private theirPubKey!: CryptoKey;
  private secret!: ArrayBuffer;
  private ready!: Promise<boolean>;

  private utils = new CryptUtils();

  constructor(
    ourPrivKey : CryptoKey,
    keyId:       string,
    theirPubKey: CryptoKey
  ) {

    this.ourPrivKey  = ourPrivKey;
    this.keyId       = keyId;
    this.theirPubKey = theirPubKey;

    this.ready = new Promise<boolean>(( resolve ) => {

      deriveSecret( ourPrivKey, theirPubKey )
        .then( (secret) => { this.secret = secret; resolve(true) } )
        .catch( (error) => { throw new Error('Failed to derive secret'+ error );  } ); 
    });

  }

  public async encrypt( 
    encipherText: string 
  ) {

    await this.ready;

    return bufToBase64URL( await encryptWithSecret( encipherText, this.secret ) ); 
  }

  public async decrypt( 
    saltCipherTagEnc: string 
  ) {

    await this.ready;

    const buf = new Uint8Array(base64URLToBuf(saltCipherTagEnc));

    return decryptWithSecret( buf, this.secret );
  }

  public async getOurPubKey() {

    const jwkPrivate = await SUBTLE.exportKey("jwk", this.ourPrivKey ); 

    delete jwkPrivate.d;

    jwkPrivate.key_ops = [];

    return SUBTLE.importKey(
      "jwk", 
      jwkPrivate, 
      {
         name: 'X25519'
      },
      true, 
      []
    );
  } 

  public async getOurPubKeyEncoded() {
    return this.utils.exportKeyEncoded( await this.getOurPubKey() );
  }

}

export class CryptUtils {

  public async passphraseToX25519(
    passphrase: string,
    salt:       ArrayBuffer,
    idBuf:      Uint8Array
  ) {
   return passphraseToX25519( passphrase, salt, idBuf );
  }

  public async encryptKeyV1(
    pk:        CryptoKey,
    lockPubPk: CryptoKey,
    idBuf:     Uint8Array,
    salt:      Uint8Array<ArrayBuffer>
  ) {
    return encryptKeyV1( pk, lockPubPk, idBuf, salt );
  }

  public async getPubKey(
    pk:        CryptoKey,
  ) {

    const jwkPrivate = await SUBTLE.exportKey("jwk", pk ); 

    delete jwkPrivate.d;

    jwkPrivate.key_ops = [];

    return SUBTLE.importKey(
      "jwk", 
      jwkPrivate, 
      {
         name: 'X25519'
      },
      true, 
      []
    );
  } 

  public idToUuid(
     id: string
  ) {
     return uuidBufToUuid( idToUuidBuf(id) )
  }
  public idToUuidBuf( 
     id: string
  ) {
    return idToUuidBuf(id)
  }

  public base64UrlToBuf(
    str: string 
  ) {
    return base64URLToBuf( str );
  }

  public bufToBase64Url(
    buf: ArrayBuffer 
  ) {
    return bufToBase64URL( buf );
  }

  public async exportKey(
    key: CryptoKey 
  ) {
    return exportKey( key );
  }

  public async exportKeyEncoded( 
    key: CryptoKey 
  ) {
    return exportKeyEncoded(key); 
  }

  public hex2buf( 
    str: string
  ) {
    return hex2buf(str)
  }

  public bufToHex(
    buf: Uint8Array 
  ) {
    return Array.from( buf ).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}