import { expect, assert } from "chai";
import util from 'node:util';
import { readFile } from 'fs/promises';
import ece from 'http_ece';

import {
  CryptUtils,
  unlockLoginKey,
  loadPrivateKey,
  loadPublicKey,
  signTokens,
  verifyTokens,
  verifyPublicKey,
  verifyPublicKeyAndSigner,
  deriveSecret,
  decryptWithSecret,
  eceEncrypt,
  eceDecrypt,
  eceDecrypt2,
  unlockApiKey
} from '../dist/excollect-client/crypt.js';

const utils = new CryptUtils();

const vectorData = JSON.parse(await readFile("test/data/test_vectors.json", "utf8"));
const loginData  = JSON.parse(await readFile("test/data/login_response.json", "utf8"));

//console.log(util.inspect(vectorData, {showHidden: false, depth: null, colors: true} ));

const certificates      = vectorData['certificates'];
const tokenTests        = vectorData['signed_tokens'];
const encryptedPayloads = vectorData['encrypted_payloads'];
const loginKeys         = vectorData['login_keys'];

describe( 'Token Signatures', function() {

   for ( const tokenTest of tokenTests ) {

     describe( tokenTest['name'], function() {
       verifyTokenSignature( tokenTest );
     });
   }
});

describe( 'Expected Verifcation Failures', function() {

  const test   = tokenTests[0];
  const tokens = test['tokens']

  it ( 'Incorrect public key', async function () {

    const serverSig  = test['sig'];
    const publicKey  = 'MCowBQYDK2VwAyEAJJmARhNg_JOr84RXDA5CLDf4E3iCBasXh836hsxv6o0';
    const pubPk      = await loadPublicKey(publicKey);
    const verified   = await verifyTokens(tokens, serverSig, pubPk);

    assert.isFalse(verified);
  });

  it ( 'Bad Signature', async function () {

    const serverSig  = 'BADSIG';
    const publicKey  = test['user']['public_key']
    const pubPk      = await loadPublicKey(publicKey);
    const verified   = await verifyTokens(tokens, serverSig, pubPk);

    assert.isFalse(verified);
  });

  it ( 'Altered tokens', async function () {

    const serverSig  = test['sig'];
    const publicKey  = test['user']['public_key']
    const pubPk      = await loadPublicKey(publicKey);
    const badTokens  = structuredClone(tokens);

    badTokens['Content'] = 'BADBAD';

    const verified   = await verifyTokens(badTokens, serverSig, pubPk);

    assert.isFalse(verified);
  });

});

describe( 'Encrypted data', function() {

  for ( const payload of encryptedPayloads ) {

    describe( payload['name'], function() {

      const edhPriv  = payload['edh_priv'];
      const theirPub = payload['server_pub'];
      const cipher   = new Uint8Array( utils.base64UrlToBuf( payload['cipher'] ) );
      const plain    = payload['plain'];

      it ( 'should decrypt data', async function () {

        const ourPrivatePk = await loadPrivateKey(edhPriv, 'x25519');
        const theirPubPk   = await loadPublicKey(theirPub, 'x25519');
        const secret       = await deriveSecret( ourPrivatePk, theirPubPk );
        const decrypted    = await decryptWithSecret( cipher, secret );

        assert.equal( decrypted, plain );
      });

    });
  }
});

describe( 'Ed25519 Certiicates', function() {

  const rootCertificate    = certificates['root'];
  const signerCertificates = certificates['signers'];

  for ( const certificate of signerCertificates ) {

    describe( certificate['id'], async function () {

      it ( 'verify certifcate', async function () {

          const rootPubPk = await loadPublicKey(rootCertificate['public_key']);
          const verified  = await verifyPublicKey(certificate, rootPubPk);

          assert.isTrue(verified);
      });

      it ( 'load certicate', async function () {

        const ecdhPubPk  = await loadPublicKey(certificate['public_key']);

        assert.instanceOf( ecdhPubPk, CryptoKey );

      });
    });
  }
});

describe( 'x25519 Certiicates', function() {

  const rootCertificate = certificates['root'];
  const dhCertificates  = certificates['dh'];

  for ( const certificate of dhCertificates ) {

    describe( certificate['id'], async function () {

      it ( 'verify certicate', async function () {

          const rootPubPk = await loadPublicKey(rootCertificate['public_key']);
          const verified  = await verifyPublicKeyAndSigner( certificate, rootPubPk);

          assert.isTrue(verified);
      });

      it ( 'load certicate', async function () {

        const ecdhPubPk  = await loadPublicKey(certificate['public_key'], 'x25519');

        assert.instanceOf( ecdhPubPk, CryptoKey );

      });

    });
  }
});

// TODO update test data
await describe.skip( 'Login Keys', async function() {

  const rootCertificate = certificates['root'];

  for ( const login of loginKeys  ) {

    const loginKey     = login['key'];
    const loginKeyData = login['key_data'];
    const passphrase   = login['pass'];
    const apiKeys      = login['api_keys'];

    describe( loginKey['id'], async function () {

        it ( 'login key decrypt', async function () {
           this.skip();

           const {loginPrivPk} = await unlockLoginKey( loginKeyData, passphrase, loginKey['owner_id'] );

           assert.instanceOf( loginPrivPk, CryptoKey );
        });

        for ( const api of apiKeys ) {
          const apiKey     = api['key'];
          const apiKeyData = api['key_data'];

          it ( apiKey['id'] +' unlocked' , async function () {

            const {loginPrivPk} = await unlockLoginKey( loginKeyData, passphrase, loginKey['owner_id'] );
            const {apiPrivPk}   = await unlockApiKey(apiKeyData, loginPrivPk, apiKey['owner_id']);

            assert.instanceOf( apiPrivPk, CryptoKey );
          });
        }

    });
  }
});

function verifyTokenSignature( test )  {

  const serverSig  = test['sig'];
  const tokens     = test['tokens']
  const privateKey = test['user']['private_key'];
  const publicKey  = test['user']['public_key'];

  it ( 'should verify with server signature', async function () {

    const pubPk = await loadPublicKey(publicKey);

    assert.instanceOf( pubPk, CryptoKey );

    const verified = await verifyTokens( tokens, serverSig, pubPk );

    assert.isTrue(verified);
  });

  it ( 'should verify with matching client signature', async function () {

    const pubPk  = await loadPublicKey(publicKey);
    const privPk = await loadPrivateKey(privateKey);

    assert.instanceOf( privPk, CryptoKey );

    const clientSig = await signTokens( tokens, privPk );
    const verified  = await verifyTokens( tokens, clientSig, pubPk );

    assert.isTrue(verified);
    assert.equal( serverSig, clientSig );

  });

}

describe( 'RFC8188 Encrypted data', function() {


  it ( 'Should Decrpyt', async function() {

    const secret    = utils.base64UrlToBuf('PlQyPFA2ipYjWZ5DLrCQKREUNscbvlOJxFuF58f62DY');
    const cipher    = 'nPfsNxoMfT9d3HBVYF5OVQAAEAAA6PsINR7c_mzG-LduvCT5SBL2nAeNsCTUO70Y2qiT';
    const plainText = 'fooo bar weee'

    const plain = await eceDecrypt2( cipher, secret );

    assert.equal( plain, plainText );
  });
});
