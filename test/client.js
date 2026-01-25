import crypto from "crypto";
import { expect, assert } from "chai";
import dayjs from 'dayjs';
import AxiosMockAdapter from 'axios-mock-adapter'; 
import {Axios} from 'axios'; 
import { 
  getCurrentTimeStamp,
  getTimeStamp,
  getCurrentTime
} from '../dist/excollect-client/utils.js';
import { ExCollectClient } from '../dist/excollect-client.js';
import { 
  createEd25519Keys,
  createX25519Keys,
  CryptUtils,
  Encryptor,
  loadPublicKey,
  signPublicKey,
  lockApiKey
} from '../dist/excollect-client/crypt.js'; 
import util from 'node:util';

const utils = new CryptUtils();

const { keyData: rootData, privateKey: rootPk }      = await createRootKey();
const { keyData: signerData,  privateKey: signerPk } = await createSignerKey( rootPk, rootData );

describe("Client constructor", function() { 

  it( 'should error without rootAuthority', async function () {

    try {

      await new ExCollectClient({
            "apiUrl": 'http://localhost/api',
          }).ready;
    }
    catch (error) {
      assert.instanceOf(error, Error);
      assert.equal( error.message, 'Setup error: Must set rootAuthority' )
    }

  });

  it( 'should error on bad rootAuthority', async function () {

    try {

      await new ExCollectClient({
              "apiUrl": 'http://localhost/api',
              "rootAuthority": { public_key: "sdafsd"}
            }).ready;
    }
    catch (error) {
      assert.instanceOf(error, Error);
      assert.equal( error.message, 
                    'Setup error: Root Authority failed to loadDataError: Invalid keyData' );
    }

  });

  it( 'ready should return instance', async function () {

    const client = await new ExCollectClient({
            "apiUrl": 'http://localhost/api',
            "rootAuthority": rootData 
          }).ready;

    assert.instanceOf( client, ExCollectClient ); 

  });
});

const { 
  keyData:       loginKeyData, 
  privateKey:    loginPk, 
  publicKey:     loginPubPk, 
  privateKeyEnc: loginPrivEnc
} = await createLoginKey( 
  signerData, 
  signerPk, 
  'ASskjvsk2kss#asdf!' 
);

const userUuid = idToUUID( loginKeyData.owner_id ); //createUUID();
const apiKeys  = await createApiKeys( signerData, signerPk, userUuid, loginPubPk) ;

describe("Client instance load keys", function() { 

  const client = new ExCollectClient({ 
    "apiUrl":        'http://localhost/api',
    "userId":         loginKeyData.owner_id, 
    "rootAuthority": rootData,
  });

  let mock;
  client.ready.then( () => {
    mock = new AxiosMockAdapter(client.userAgent, { delayResponse: 0 });
  });
  
  it( 'loadKeyData', async function () { 

    await client.ready;
    await client.loadKeyData( loginKeyData.owner_id, loginPrivEnc, apiKeys );

    //assert.isDefined(client.loginPrivEnc);  
    assert.instanceOf(client.loginPk, CryptoKey, 'client pk object set on ready');
    assert.instanceOf(client.activeUserKey.privPk, CryptoKey, 'account user pk object set on ready');
    assert.instanceOf(client.activeAccKey.privPk, CryptoKey, 'account pk object set on ready');
    assert.instanceOf(client.activeExcKey.privPk, CryptoKey, 'excollect pk object set on ready');

  });

  it( 'add Key', async function () { 

    await client.ready;

    const e_context = {
      'api':       'excollect',
      'site':      createUUID(),
      'site_user': createUUID()    
    };
    const { keyData: eKeyData, privateKey: ePk } = await createApiKey( 
        'exc', 
        e_context, 
        signerData, 
        signerPk, 
        loginPubPk );

    await client.addApiKeys([eKeyData]);

    assert.equal(client.activeExcKey.data.id, eKeyData.id);
    assert.equal( client.apiKeys.length, 4);

  });



});

describe("Client instance constructed With Login Key", function() { 

  const client = new ExCollectClient({ 
    "apiUrl":        'http://localhost/api',
    "userId":        loginKeyData.owner_id, 
    "loginPrivEnc":  loginPrivEnc,
    "rootAuthority": rootData,
    "apiKeys":       apiKeys 
  });

  let mock;
  client.ready.then( () => {
    mock = new AxiosMockAdapter(client.userAgent, { delayResponse: 0 });
  });

  it( 'should return client', async function () {

    assert.instanceOf(client, ExCollectClient, 'client is instance of ExCollectClient');
  });

  it( 'should have private keys set on ready', async function () { 

    await client.ready;

    // assert.isDefined(client.loginPrivEnc);  
    assert.instanceOf(client.loginPk, CryptoKey, 'client pk object set on ready');
    assert.instanceOf(client.activeUserKey.privPk, CryptoKey, 'account user pk object set on ready');
    assert.instanceOf(client.activeAccKey.privPk, CryptoKey, 'account pk object set on ready');
    assert.instanceOf(client.activeExcKey.privPk, CryptoKey, 'excollect pk object set on ready');

  });

  it( 'should have user agent set on ready', async function () { 

    await client.ready;

    assert.instanceOf(client.userAgent, Function, 'client userAgent object set on ready');

  });

  it( 'is logged in', async function () { 

    await client.ready;

    assert.isTrue(client.isLoggedIn(), 'logged in valid private key set');

  }); 

  it( 'should update time offset', async function () { 

    await client.ready;

    assert.isTrue(client.needsTimeOffsetUpdate); 

    mock.onPost("/time_offset").reply(
       200, 
      {
        "request_id" : "sdfasdfa",
        "message"    : {
            "offset": 2
        }
      }
    );

    const offset = await client.getTimeOffset(); 

    assert.equal(offset, 2);
    assert.isFalse(client.needsTimeOffsetUpdate);
  });

  it( 'time offset request error', async function () { 

    await client.ready;

    client.needsTimeOffsetUpdate = true; 

    mock.onPost("/time_offset").reply(
      500, 
      {
        "request_id" : "sdfasdfa",
        "message"    : {
            "error": "Oops" 
        }
      }
    );

    const offset = await client.getTimeOffset(); 

    assert.equal(offset, 0);
    assert.isTrue(client.needsTimeOffsetUpdate);
  });

  it( 'Get request', async function () { 

    await client.ready;

    mock.onPost("/time_offset").reply(
       200, 
      {
        "request_id" : "sdfasdfa",
        "message"    : {
            "offset": 2
        }
      }
    );

    mock.onGet("/").reply( ( config ) => { 

      return [
         200, 
         {
           "request_id" : "sdfasdfa",
           "data" : { "some" : "data" }
         }
      ]
    });

    const resp = await client.get('/'); 

    assert.equal(resp.status, 200); 

  }); 

  it( 'should fetch server ECDH pub key', async function () { 

    await client.ready;

    const { keyData, privateKey } = await createServerECHDKey( signerData, signerPk);

    mock.onGet('/account_api/users/login_dh_key').reply(
      200, 
      {
        "request_id" : "sdfasdfa",
        "message": keyData 
      }
    );

    const { theirPublicPk: ecdhKey } = await client.fetchServerDhKey(); 

    assert.instanceOf( ecdhKey, CryptoKey );

    assert.equal( ecdhKey.algorithm.name, 'X25519'); 

  }); 

}); 


describe("Client login", function() { 

  const client =  new ExCollectClient({
                    "apiUrl": 'http://localhost/api',
                    "rootAuthority": rootData 
                  });

  let mock;
  client.ready.then( () => {
    mock = new AxiosMockAdapter(client.userAgent, { delayResponse: 0 });
  });

  it( 'should log in', async function () {

    await client.ready;

    const { 
      keyData: theirKeyData, 
      publicKey: theirPublicPk,
      privateKey: theirPrivatePk,
    } = await createServerECHDKey(signerData, signerPk);

    mock.onGet('/account_api/users/login_dh_key').reply(
      200, 
      {
        "request_id" : "sdfasdfa",
        "message": theirKeyData 
      }
    );

    const passphrase = 'Svksd#askdfj@3J!';
    const loginResp  = await createLoginResponse( signerData, signerPk, passphrase );
    //console.log( util.inspect( loginResp, {showHidden: false, depth: null, colors: true}) );

    mock.onPost('/account_api/users/login_user')
        .reply( async (config) => {

          const postData         = JSON.parse( config['data'] );
          const passphraseCipher = postData['password'];
          const pubKey           = postData['edh']['public_key'];
          const keyId            = postData['edh']['dhk_id']; 
          const ourPublicPk      = await loadPublicKey( pubKey, 'x25519' );
          const encryptor        = new Encryptor( theirPrivatePk, keyId, ourPublicPk );
          const passphrasePlain  = await encryptor.decrypt( passphraseCipher );

          assert.equal( passphrasePlain, passphrase );

          return [
            200, 
            {
              "request_id" : "sdfasdfa",
              "message": { 
                "data" : {
                   "login_key": loginResp              
                }
              }
            }
          ];
        });

    const resp = await client.logIn('mockUser', passphrase );

    assert.equal( resp.status, 200); 
    assert.isDefined(client.loginPk); 
    assert.isTrue(client.isLoggedIn());

  });

}); 

async function createServerECHDKey(
   signerData,
   signerPk
) {

  const { publicKey, privateKey } = await createX25519Keys(); 

  const keyData = {
    "id":          createId('ecdhk'),
    "owner_id":    createId('ecdhk'),
    "created":     getCurrentTimeStamp(),
    "public_key":  await utils.exportKeyEncoded(publicKey),
  };

  keyData['signature'] = await signPublicKey( keyData, signerPk ); 
  keyData['signed_by'] = signerData; 

  return { keyData, privateKey, publicKey };
}

async function createRootKey() {
  
  const { publicKey, privateKey } = await createEd25519Keys(); 
  const keyData                   = await createKeyData('ca', publicKey )

  keyData['signature'] = await signPublicKey( keyData, privateKey ); 
  keyData['signed_by'] = keyData['id'];

  return { keyData, privateKey };
}

async function createEncryptor(
   theirKeyId, 
   theirPublicPk,
) {
   const { privateKey: ourPrivatePk } = await createX25519Keys();

   return new Encryptor( ourPrivatePk, theirKeyId, theirPublicPk );
}



async function createSignerKey(
   rootPk,
   rootKeyData
) {
  
  const { publicKey,  privateKey } = await createEd25519Keys(); 
  const keyData                    = await createKeyData('ca', publicKey )

  keyData['signature'] = await signPublicKey( keyData, rootPk ); 
  keyData['signed_by'] = rootKeyData['id'];

  return { keyData, privateKey };
}

async function createLoginResponse( 
   sKeyData,
   sPk,
   passphrase = 'Tsd23$sdfk12Cvf2'
) {

  const { 
    keyData: lKeyData, 
    privateKey: lPk, 
    publicKey: lPubPk 
  } = await createLoginKey( 
    sKeyData, 
    sPk, 
    passphrase 
  );

  const userUuid = idToUUID( lKeyData.owner_id );
  const apiKeys   = await createApiKeys( sKeyData, sPk, userUuid, lPubPk) ;

  return {
    'api_keys': apiKeys,
    ...lKeyData
  }
}

async function createApiKeys( 
   sKeyData,
   sPk,
   user_uuid,
   lPubPk
) {

  const au_context = {
    'account_user': user_uuid,
    'api':          'account_user'
  };
  const { keyData: uKeyData, privateKey: uPk } = await createApiKey( 'au', au_context, sKeyData, sPk, lPubPk );

  const a_context = {
    'account':      createUUID(),
    'account_user': user_uuid,
    'api':          'account'
  };
  const { keyData: aKeyData, privateKey: aPk } = await createApiKey( 'act', a_context, sKeyData, sPk, lPubPk );

  const e_context = {
    'api':       'excollect',
    'site':      createUUID(),
    'site_user': createUUID()    
  };
  const { keyData: eKeyData, privateKey: ePk } = await createApiKey( 'exc', e_context, sKeyData, sPk, lPubPk );

  return  [ uKeyData, aKeyData, eKeyData ] 
}

async function createLoginKey( 
   signerKeyData,
   signerPk,
   passphrase
) {
  const { publicKey, privateKey } = await createX25519Keys(); 
  const keyData                   = await createKeyData( 'lgn', publicKey );

  const idBuf           = utils.idToUuidBuf(keyData.owner_id);
  const salt            = crypto.getRandomValues(new Uint8Array(32));
  const passphraseSalt  = Buffer.from(salt).reverse();

  const passphrasePk    = await utils.passphraseToX25519( passphrase, passphraseSalt, idBuf );
  const passphrasePubPk = await utils.getPubKey(passphrasePk);
  const keyBuffer       = await utils.encryptKeyV1( privateKey, passphrasePubPk, idBuf, salt );

  keyData['context']   = {};
  keyData['signature'] = await signPublicKey( keyData, signerPk ); 
  keyData['signed_by'] = signerKeyData;
  keyData["key_data"]  = utils.bufToBase64Url(keyBuffer);

  const privateKeyEnc = await utils.exportKeyEncoded(privateKey);

  return { keyData, privateKey, privateKeyEnc, publicKey };
}

async function createApiKey( 
   keyType,
   context,
   signerKeyData,
   signerPk,
   loginPubPk
) {
  const { publicKey, privateKey } = await createEd25519Keys(); 
  const keyData                   = await createKeyData( keyType, publicKey )

  keyData['context']   = context;
  keyData['signature'] = await signPublicKey( keyData, signerPk ); 
  keyData['signed_by'] = signerKeyData;
  keyData['key_data']  = await lockApiKey( privateKey, loginPubPk, keyData['owner_id'] );

  return { keyData, privateKey };
}

async function createKeyData(
   keyType,
   signPubPk,
   ownerId = createId(keyType)
) {

  const keyData = {
    "id":          createId( keyType +'k' ),
    "owner_id":    ownerId, //createId(keyType),
    "created":     getCurrentTimeStamp(),
    "expires":     getTimeStamp( getCurrentTime().add(20,'year') ),
    "public_key":  await utils.exportKeyEncoded(signPubPk)
  };

  return keyData
}


function createId( prefix ) {
    const randomHex = crypto.randomBytes(16).toString("hex");

    return  prefix +'_'+ randomHex; 
}

function idToUUID( id ) {
    const buf = utils.idToUuidBuf(id)

    // b4b1e350-c13b-4063-8157-1a0beb251b22
    // bac05059-7bec-42a1-a2e8-29849b160a07

    return utils.bufToHex( buf.slice(0,4) ) 
           +'-'+ utils.bufToHex( buf.slice(4,6) )
           +'-'+ utils.bufToHex( buf.slice(6,8) )
           +'-'+ utils.bufToHex( buf.slice(8,10) )
           +'-'+ utils.bufToHex( buf.slice(10,16) );

}

function createUUID() {
    return crypto.randomUUID(); 
}