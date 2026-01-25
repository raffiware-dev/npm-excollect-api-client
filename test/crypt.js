import { expect, assert } from "chai";
import dayjs from 'dayjs';
import AxiosMockAdapter from 'axios-mock-adapter'; 

import { 
  getCurrentTimeStamp, 
  getCurrentTime,
  getTimeStamp
} from '../dist/excollect-client/utils.js'; 
import { 
  generateNonce,
  generateMsgFromTokens, 
  loadPrivateKey,
  loadPublicKey,
  signTokens,
  verifyTokens,
  signCommandInstance,
  signApiRequest,
  createSignedDhKey,
  verifySignedDhKey,
  createKeyChangeAuthorization,
  createEd25519Keys,
  createX25519Keys,
  signPublicKey,
  verifyPublicKey,
  verifyPublicKeyAndSigner,
  deriveSecret,
  lockApiKey,
  unlockApiKey,
  encryptWithSecret,
  decryptWithSecret,
  eceEncrypt,
  eceDecrypt,
  eceEncrypt2,
  eceDecrypt2,
  Encryptor,
  CryptUtils
} from '../dist/excollect-client/crypt.js';

const utils = new CryptUtils();

describe("generateNonce", function() { 

   it( 'should return 32bit number', function () {

     const nonce = generateNonce();
     assert.isDefined( nonce );
     assert.isAtLeast( nonce, 0x40000000 );
     assert.isAtMost( nonce, 0xffffffff );
   });
});

describe("generateMsgFromTokens ", function() { 

   it( 'should return message', function () {

     const dc = new TextDecoder(); 

     const tokens = {
       "this":"that",
       "foo":"bar",
       "bizz":"bazz"
     };
     const msg = generateMsgFromTokens(tokens);  

     assert.isDefined( msg );
     assert.strictEqual( dc.decode(msg), 'bazz,bar,that', 'got token values sorted by keys in string');
   });

});

// public_key: MCowBQYDK2VwAyEANeCln2kp5nJhAnUPEs98bIy-juo1-wzcydMGH_FQ-uo
// private_key: MC4CAQAwBQYDK2VwBCIEILOdEQQNVYhyn8W1XNa0ENqLma21SGePP6cBdLLpwI1L

describe("loadPrivateKey", function() { 

  const privateKey = 'MC4CAQAwBQYDK2VwBCIEILOdEQQNVYhyn8W1XNa0ENqLma21SGePP6cBdLLpwI1L'; 

  it( 'should return key', async function () {

    const pk = await loadPrivateKey(privateKey);

    assert.isDefined( pk );
    assert.instanceOf( pk, CryptoKey ); 
  });

}); 

describe("loadPublicKey", function() { 

  const publicKey = 'MCowBQYDK2VwAyEANeCln2kp5nJhAnUPEs98bIy-juo1-wzcydMGH_FQ-uo';

  it( 'should return key', async function () {

    const pk = await loadPublicKey(publicKey); 

    assert.isDefined( pk );
  });

});

describe("signTokens", function() { 

  const privateKey = 'MC4CAQAwBQYDK2VwBCIEILOdEQQNVYhyn8W1XNa0ENqLma21SGePP6cBdLLpwI1L';  

  it( 'should return signature', async function () {

    const tokens = {
        "header":"vallue",
        "date": "time",
        "this": "that thing"
    };

    const pk  = await loadPrivateKey(privateKey); 
    const sig = await signTokens(tokens, pk); 

    assert.isDefined( sig );
  });

});

describe("verifyTokens", function() { 

  const privateKey = 'MC4CAQAwBQYDK2VwBCIEILOdEQQNVYhyn8W1XNa0ENqLma21SGePP6cBdLLpwI1L';  
  const publicKey  = 'MCowBQYDK2VwAyEANeCln2kp5nJhAnUPEs98bIy-juo1-wzcydMGH_FQ-uo';

  const tokens = {
      "header":"vallue",
      "date": "time",
      "this": "that thing"
  };

  it ( 'should verify signature', async function () {

    const privPk  = await loadPrivateKey(privateKey);
    const pubPk   = await loadPublicKey(publicKey);
    const sig     = await signTokens(tokens, privPk); 

    const verified = await verifyTokens(tokens, sig, pubPk);

    assert.isTrue(verified);
  }); 

  it( 'should not verify signature', async function () { 

    const privPk  = await loadPrivateKey(privateKey);
    const pubPk   = await loadPublicKey(publicKey);
    const sig     = await signTokens(tokens, privPk);  

    const badTokens = {
        "header":"vallue",
        "date": "time",
        "this": "that thing!"
    };

    const notVerified = await verifyTokens(badTokens, sig, pubPk);

    assert.isFalse(notVerified);
  });

}); 

describe("signCommandInstance", function() { 

  const keyId      = 'exck_FFFSdfaskj234';
  const privateKey = 'MC4CAQAwBQYDK2VwBCIEILOdEQQNVYhyn8W1XNa0ENqLma21SGePP6cBdLLpwI1L';  

  it( 'should return signature', async function () {

    const commandInstance = {
      "site":             "s_6e6180bd715e4fae93e58562f57fa58c",
      "created_datetime": "2025-06-05T20:41:21.165+00:00",
      "signed_by":        "su_6b3d35828dfe4502be0affc8009db8d9",
      "id":               "ci_6b7684d4ccfb4b61910ad43a9dac73b8",
      "command":          "c_8c00442bf4bf422c9241c86b0c42521e",
      "execute_type":     "bin",
      "command_string":   "/bin/uptime" ,
      "client_jobs":         []
    };

    const pk  = await loadPrivateKey(privateKey); 
    const { signature } = await signCommandInstance(commandInstance, keyId, pk); 

    assert.isDefined( signature );
  });

  it( 'should return signature', async function () {

     const commandInstance = {
       "site":             "s_6e6180bd715e4fae93e58562f57fa58c",
       "created_datetime": "2025-06-05T20:41:21.165+00:00",
       "signed_by":        "su_6b3d35828dfe4502be0affc8009db8d9",
       "id":               "ci_6b7684d4ccfb4b61910ad43a9dac73b8",
       "command":          "c_8c00442bf4bf422c9241c86b0c42521e",
       "execute_type":     "script",
       "command_string":   "/bin/uptime",
       "script_src": `
#!/bin/bash

echo "hello world"
`,
      "client_jobs":         []
    };

    const pk  = await loadPrivateKey(privateKey); 
    const { signature  } = await signCommandInstance(commandInstance, keyId, pk); 

    assert.isDefined( signature );
    console.log(signature);
  }); 

});

describe("signApiRequest", function() { 

  const keyId      = 'uk_FFFSdfaskj234';
  const privateKey = 'MC4CAQAwBQYDK2VwBCIEILOdEQQNVYhyn8W1XNa0ENqLma21SGePP6cBdLLpwI1L';  

  it( 'should return signature', async function () {

    const pk  = await loadPrivateKey(privateKey);

    const reqCfg = {
        "url"    : "/some/path",
        "method" : "get",
        "baseURL": "http://test.dev/api"
    };

    const opts = {
       "keyId":      keyId,
       "pk":         pk,
       "timeOffset": 2,
    };

    const signedReqCfg = await signApiRequest( reqCfg, opts );

    assert.isDefined( signedReqCfg );
  });

}); 

describe("createEd25519Keys", function() {

  it( 'should return keys', async function () {

    const { publicKey, privateKey } = await createEd25519Keys();

    assert.instanceOf( publicKey, CryptoKey );
    assert.instanceOf( privateKey, CryptoKey );
  });

});  

describe("createX25519Keys", function() {

  it( 'should return keys', async function () {

    const { publicKey, privateKey } = await createX25519Keys();

    assert.instanceOf( publicKey, CryptoKey );
    assert.instanceOf( privateKey, CryptoKey );
  });

});  

describe("deriveSecret", function() {

  it( 'should return 32byte secret', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const secret = await deriveSecret( ourPrivatePk, theirPublicPk );

    assert.isDefined( secret );
    assert.equal( secret.byteLength, 32 );
  });

  //it( 'should return 16byte secret', async function () {

  //  const { privateKey: ourPrivatePk } = await createX25519Keys();
  //  const { publicKey: theirPublicPk } = await createX25519Keys();

  //  const secret = await deriveSecret( ourPrivatePk, theirPublicPk, 128 );

  //  assert.isDefined( secret );
  //  assert.equal( secret.byteLength, 16 );
  //});

}); 

describe("encryptWithSecret", function() {

  it( 'should encrypt', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const secret        = await deriveSecret( ourPrivatePk, theirPublicPk );
    const saltCipherTag = await encryptWithSecret('test encrypt this', secret );

    assert.isDefined( saltCipherTag );
    //assert.equal( secret.byteLength, 32 );
  });

}); 

describe("decryptWithSecret", function() {

  it( 'should decrypt', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const encipher      = 'test encrypt this';
    const secret        = await deriveSecret( ourPrivatePk, theirPublicPk );
    const saltCipherTag = await encryptWithSecret( encipher, secret );
    const plain         = await decryptWithSecret( saltCipherTag, secret );

    assert.isDefined( plain );
    assert.equal( plain, encipher );
  });

}); 

describe("Encryptor instance", function() {

  it( 'should encrypt and decrypt', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const encryptor = new Encryptor( ourPrivatePk, 'uk_fffff', theirPublicPk );

    assert.instanceOf( encryptor, Encryptor );

    const encipherText = 'SomeImportSecretText!';
    assert.equal( await encryptor.decrypt( await encryptor.encrypt(encipherText) ), encipherText );
  });

  it( 'should derive ourPubKey', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const encryptor = new Encryptor( ourPrivatePk, 'uk_ffffff', theirPublicPk );

    const ourPubKey = await encryptor.getOurPubKey();

    assert.instanceOf( ourPubKey, CryptoKey );
    assert.equal( ourPubKey.type, 'public' );
  });

});

describe("signKey", function() {


  it( 'should sign and verify', async function () {

    const { publicKey, privateKey: signerPk }     = await createEd25519Keys();
    const { publicKey: toBeSignedPk, privateKey } = await createEd25519Keys();

    const keyData = {
      "id":          "cak_FFFFFFFFF",
      "owner_id":    "ca_FFFFFFFFF", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ),
      "public_key":  await utils.exportKeyEncoded(toBeSignedPk),
    };

    keyData['signature'] = await signPublicKey(keyData, signerPk ); 
    keyData['signed_by']   = {
      "id":          "cak_RRRRRRRRR",
      "owner_id":    "ca_RRRRRRRRR", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ),
      "public_key":  await utils.exportKeyEncoded(publicKey),
    };

    assert.isDefined( keyData['signature'] );

    const verified = await verifyPublicKey( keyData, publicKey );

    assert.isTrue(verified);
  });

});

describe("verifyPublicKeyAndSigner", function() {


  it( 'should sign and verify both key and signer key', async function () {

    const { publicKey: rootPubPk,   privateKey: rootPk }   = await createEd25519Keys();
    const { publicKey: signerPubPk, privateKey: signerPk } = await createEd25519Keys();
    const { publicKey: toBeSignedPk, privateKey }          = await createEd25519Keys();

    const signerData = {
      "id":          "cak_FFFFFFFFF",
      "owner_id":    "ca_FFFFFFFFF", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ), 
      "public_key":  await utils.exportKeyEncoded(signerPubPk),
    };

    signerData['signature'] = await signPublicKey( signerData, rootPk ); 
    signerData['signed_by'] = {
      "id":          "cak_RRRRRRRRR",
      "owner_id":    "ca_RRRRRRRRR", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ), 
      "public_key":  await utils.exportKeyEncoded(rootPubPk),
    };

    const keyData = {
      "id":          "uk_BBBBBBBBB",
      "owner_id":    "au_CCCCCCCCC", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ), 
      "public_key":  await utils.exportKeyEncoded(toBeSignedPk),
    };

    keyData['signature'] = await signPublicKey(keyData, signerPk ); 
    keyData['signed_by'] = signerData;

    const verified = await verifyPublicKeyAndSigner( keyData, rootPubPk );

    assert.isTrue(verified);
  });

  it( 'should throw error on signerData mismatch', async function () {

    const { publicKey: rootPubPk,   privateKey: rootPk }   = await createEd25519Keys();
    const { publicKey: signerPubPk, privateKey: signerPk } = await createEd25519Keys();
    const { publicKey: toBeSignedPk, privateKey }          = await createEd25519Keys();

    const signerData = {
      "id":          "cak_FFFFFFFFF",
      "owner_id":    "ca_FFFFFFFFF", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ), 
      "public_key":  await utils.exportKeyEncoded(signerPubPk),
    };

    signerData['signature'] = await signPublicKey( signerData, rootPk ); 
    signerData['signed_by']   = {
      "id":          "cak_RRRRRRRRR",
      "owner_id":    "ca_RRRRRRRRR", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ), 
      "public_key":  await utils.exportKeyEncoded(rootPubPk),
    };

    const keyData = {
      "id":          "uk_BBBBBBBBB",
      "owner_id":    "au_CCCCCCCCC", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ),
      "public_key":  await utils.exportKeyEncoded(toBeSignedPk),
    };

    keyData['signature']       = await signPublicKey(keyData, signerPk ); 
    keyData['signed_by']       = signerData;

    /* corrupt data */
    keyData['signed_by']['id'] = 'ca_EEEEEEEEE'; 

    try {
      const verified = await verifyPublicKeyAndSigner( keyData, rootPubPk );
      assert.fail('Did Not Error on Bad Signer Data');
    }
    catch (error) {
      assert.instanceOf(error, Error );
    };
  }); 

  it( 'should fail on keyData mismatch', async function () {

    const { publicKey: rootPubPk,   privateKey: rootPk }   = await createEd25519Keys();
    const { publicKey: signerPubPk, privateKey: signerPk } = await createEd25519Keys();
    const { publicKey: toBeSignedPk, privateKey }          = await createEd25519Keys();

    const signerData = {
      "id":          "cak_FFFFFFFFF",
      "owner_id":    "ca_FFFFFFFFF", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ),
      "public_key":  await utils.exportKeyEncoded(signerPubPk),
    };

    signerData['signature'] = await signPublicKey( signerData, rootPk ); 
    signerData['signed_by']   = {
      "id":          "cak_RRRRRRRRR",
      "owner_id":    "ca_RRRRRRRRR", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ),
      "public_key":  await utils.exportKeyEncoded(rootPubPk),
    };

    const keyData = {
      "id":          "uk_BBBBBBBBB",
      "owner_id":    "au_CCCCCCCCC", 
      "created":     getCurrentTimeStamp(),
      "expires":     getTimeStamp( getCurrentTime().add(1,'year') ),
      "public_key":  await utils.exportKeyEncoded(toBeSignedPk),
    };

    keyData['signature'] = await signPublicKey(keyData, signerPk ); 
    keyData['signed_by'] = signerData;

    /* corrupt data */
    keyData['id']        = 'ok_EEEEEEEEE'; 

    const verified = await verifyPublicKeyAndSigner( keyData, rootPubPk );

    assert.isFalse(verified);
  }); 


}); 

describe("lockApiKey", function() {

  it( 'should lock and unlock key', async function () {

    const { publicKey: publicLoginKey, privateKey: privateLoginKey } = await createX25519Keys();
    const { publicKey: publicApiKey,   privateKey: privateApiKey }   = await createEd25519Keys();

    const keyId  = 'exck_1111111111';
    const locked = await lockApiKey(privateApiKey, publicLoginKey, keyId );

    const unlockedPk = await unlockApiKey( locked, privateLoginKey, keyId );

    assert.instanceOf( unlockedPk.apiPrivPk, CryptoKey );


  });

}); 

describe("createKeyChangeAuthorization", function() {

  it( 'should create key change authorization', async function () {

    const { publicKey: publicLoginKey, privateKey: privateLoginKey } = await createX25519Keys();
    const { publicKey: publicApiKey,   privateKey: privateApiKey }   = await createEd25519Keys();

    const authorizorId  = 'au_f3acd0f16e3445a7a43e5575a7adb1ea';
/*
  authorizorId: string,
  authorizorPk: CryptoKey,
  userId:       string,
  context:      string,
  contextVal:   string,
  privileged:   number 
*/

    // 2cf88b2a-caec-4d9f-9e2b-4ddc7477104e
    // 13acd0f1-6ff4-45a7-a43e-5575a7adb1e8
    const auth = await createKeyChangeAuthorization(
      authorizorId,
      privateApiKey,
      //'au_2cf88b2acaec4d9f9e2b4ddc7477104e',
      '2cf88b2a-caec-4d9f-9e2b-4ddc7477104e',
      'site',
      's_13acd0f16ff445a7a43e5575a7adb1e8'
    );

    console.log(auth);

    //const locked = await lockApiKey(privateApiKey, publicLoginKey, keyId );

    //const unlockedPk = await unlockApiKey( locked, privateLoginKey, keyId );

    //assert.instanceOf( unlockedPk.apiPrivPk, CryptoKey );


  });

  it( 'should create key change authorization with privileged and status', async function () {

    const { publicKey: publicLoginKey, privateKey: privateLoginKey } = await createX25519Keys();
    const { publicKey: publicApiKey,   privateKey: privateApiKey }   = await createEd25519Keys();

    const authorizorId  = 'au_f3acd0f26e34f5a7a43e5575a7adb1e9';
    const auth = await createKeyChangeAuthorization(
      authorizorId,
      privateApiKey,
      '2cf88b2a-caec-4d9f-9e2b-4ddc7477104e',
      'site',
      's_13acd0f16ff445a7a43e5575a7adb1e8',
      1,
      { status: 'active '} 
    );

    console.log(auth);

    //const locked = await lockApiKey(privateApiKey, publicLoginKey, keyId );

    //const unlockedPk = await unlockApiKey( locked, privateLoginKey, keyId );

    //assert.instanceOf( unlockedPk.apiPrivPk, CryptoKey );


  });


}); 

describe("eceEncrypt", function() {

  it( 'should encrypt', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const secret  = await deriveSecret( ourPrivatePk, theirPublicPk, 128 );
    const cipher  = await eceEncrypt('test encrypt this', secret );

    assert.isDefined( cipher );
  });

}); 

describe("eceDecrypt", function() {

  it( 'should decrypt', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const encipher = 'test encrypt this';
    const secret   = await deriveSecret( ourPrivatePk, theirPublicPk );
    const cipher   = await eceEncrypt( encipher, secret );
    const plain    = await eceDecrypt( cipher,  utils.bufToBase64Url(secret) );

    assert.isDefined( plain );
    assert.equal( plain, encipher );
  });

}); 

describe("createSignedDhKey", function() {

  it( 'should create key with valid signature', async function () {

    const { publicKey: publicApiKey,   privateKey: privateApiKey }   = await createEd25519Keys();

    const keyId  = 'exck_1111111111';
    
    const { dhPubEnc, sigEnc, privateKey } = await createSignedDhKey( privateApiKey );

    assert.isDefined( dhPubEnc );
    assert.isDefined( sigEnc );
    assert.instanceOf( privateKey, CryptoKey );

    const verified = await verifySignedDhKey( dhPubEnc, sigEnc, publicApiKey )
    assert.isTrue(verified);

  });

});

describe("eceDecrypt2", function() {

  it( 'should decrypt', async function () {

    const { privateKey: ourPrivatePk } = await createX25519Keys();
    const { publicKey: theirPublicPk } = await createX25519Keys();

    const encipher = 'test encrypt this';
    const secret   = await deriveSecret( ourPrivatePk, theirPublicPk );
    const cipher   = await eceEncrypt2( encipher, secret );
    const plain    = await eceDecrypt2( cipher,  secret );

    console.log(cipher);
    assert.isDefined( plain );
    assert.equal( plain, encipher );
  });

}); 

describe("idToUuid", function() {

  it( 'should become uuid', async function () {

    const expectedUuid = 'd9427920-2a31-43fc-a1d2-7f036ab480a0';
    const uuid          = utils.idToUuid('au_d94279202a3143fca1d27f036ab480a0')

    assert.equal( uuid, expectedUuid );
  });

});