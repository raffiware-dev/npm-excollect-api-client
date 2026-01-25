/*
 *  ExCollect API Client Library 
 *
 */
import axios, { AxiosError } from 'axios';
import type {
  Axios,
  AxiosResponse,
  AxiosRequestConfig,
  InternalAxiosRequestConfig
} from 'axios';
import axiosRetry from 'axios-retry';
import type { IAxiosRetryConfig } from 'axios-retry';

import { getCurrentTimeStamp }  from './excollect-client/utils.js';
import loggerUtils from './excollect-client/logger.js';
import type { Logger } from  './excollect-client/logger.js';
import {
  signApiRequest,
  signCommandInstance as _signCommandInstance,
  createSignedDhKey as _createSignedDhKey,
  verifySignedDhKey as _verifySignedDhKey,
  createKeyChangeAuthorization as _createKeyChangeAuthorization,
  unlockApiKey   as _unlockApiKey,
  unlockLoginKey,
  loadPrivateKey,
  loadPublicKey,
  verifyPublicKeyAndSigner as _verifyPublicKeyAndSigner,
  createX25519Keys,
  Encryptor,
  deriveSecret,
  eceEncrypt2,
  eceDecrypt2,
} from './excollect-client/crypt.js';

export {
  eceEncrypt2,
  eceDecrypt2
} from './excollect-client/crypt.js';

import type {
   PubKeyData,
   EncryptedKeyData
} from './excollect-client/crypt.js';

export type {
   PubKeyData as ExcPubKeyData,
   EncryptedKeyData as ExcEncryptedKeyData
} from './excollect-client/crypt.js';


export type ExcRequestData =
  string
  | number
  | Array<ExcRequestData>
  | { [name:string]: ExcRequestData };

type ApiKeys = Array<EncryptedKeyData>;

export interface ExcSignOpts {
  keyId:      string;
  pk:         CryptoKey;
  timeOffset: number;
};

export interface CommandInstance {
  site:             string;
  created_datetime: string;
  signed_by:        string;
  id:               string;
  command:          string;
  command_string:   string;
  execute_type:     string;
  script_src:       string;
  client_jobs:      Array<{ id: string, client: { id: string }}>
};

export interface ExcResponse extends AxiosResponse {};

export interface ExcApiError {
  request_id: string;
  error_id:   string;
  error_msg:  string;
};

export interface ExcRequestConfig extends AxiosRequestConfig {
  'axios-retry'?: IAxiosRetryConfig,
};

interface ApiKey {
  data:    EncryptedKeyData, 
  privPk:  CryptoKey, 
  privEnc: string
}

interface LoginKeyData extends EncryptedKeyData { 
  "api_keys": ApiKeys 
};

interface KeyHandlerFunc {
  ( apiKey: EncryptedKeyData, apiPrivPk: CryptoKey, apiPrivEnc: string ): void
};

export interface ExcClientOpts {
  apiUrl:         string;
  rootAuthority:  PubKeyData;
  userId?:        string;
  loginPrivEnc?:  string;
  apiKeys?:       ApiKeys 
}; 

export class ExCollectClient implements ExcClientOpts {

  public apiUrl:          string;
  public rootAuthority:   PubKeyData;
  public userId?:         string;
  public ready:           Promise<ExCollectClient>;
  /* These are public so the Angular app
     can cache them in local storage 
   */
  public loginPrivEnc?:    string;
  public apiKeys?:         ApiKeys;
  public activeUserKey?:  ApiKey;
  public activeAccKey?:   ApiKey;
  public activeExcKey?:   ApiKey;

  private rootAuthorityPk!: CryptoKey;
  private userAgent!:       Axios;
  private logger!:          Logger;
  private loginPk?:        CryptoKey;

  private needsTimeOffsetUpdate = true;
  private timeOffset: number    = 0;

  /**
   * @param {ExcClientOpts} opts                 Constructor parameters.
   * @param {string}        opts.apiUrl          Base API URL.
   * @param {PubKeyData}    opts.rootAuthority   PubKeyData containing Root Authority certificate.
   * @param {string}        [opts.userId]        User Id.
   * @param {string}        [opts.LoginPrivEnc]  Base64Url encoded x25519 Login Private Key
   * @param {ApiKeys}       [opts.ApiKeys]       API key data.
   * 
   */
  constructor( 
    opts: ExcClientOpts 
  ) {
 
    if ( opts.apiUrl === undefined ) {
      throw new Error('apiUrl not set');
    }

    this.apiUrl        = opts.apiUrl;
    this.rootAuthority = opts.rootAuthority;

    this.logger = loggerUtils.getLogger();

    const keysLoaded = this.loadKeys(opts);

    this.userAgent = this.buildUserAgent(); 
    this.ready     = Promise.all([keysLoaded])
      .then( () => { 
        // When all keyLoaded promises resolve true
        // resolve to our client object
        return Promise.resolve(this); 
      })
      .catch( (error) => {
        throw new Error('Setup error: '+ error );
      });
  }

  private loadKeys( opts: ExcClientOpts ): Promise<boolean[]> {

    const keysReady = new Promise<boolean>(( resolve, reject ) => {

      if ( !opts.userId || !opts.loginPrivEnc ) {
        return resolve(true);
      }

      return loadPrivateKey( opts.loginPrivEnc, 'x25519')
        .then( (pk) => {

           this.userId       = opts.userId       as string; 
           this.loginPrivEnc = opts.loginPrivEnc as string;
           this.loginPk      = pk;

           if ( opts.apiKeys !== undefined ) {
             return this.unlockApiKeys( opts.apiKeys, pk )
           }

           return Promise.all([ Promise.resolve(true) ])
        })
        .then( () => { resolve(true) })
        .catch( (error) => { reject('Private Key failed to load'+ error ) } );
    });

    const rootAuthorityReady = new Promise<boolean>(( resolve, reject ) => {

      if ( opts.rootAuthority === undefined ) { 
        reject('Must set rootAuthority'); 
      }

      return loadPublicKey(opts.rootAuthority.public_key)
        .then( (pk) => { 

           this.rootAuthority   = opts.rootAuthority;
           this.rootAuthorityPk = pk; 
           resolve(true);
        })
        .catch( (error) => { reject('Root Authority failed to load'+ error );  } );
    });

    return Promise.all([keysReady, rootAuthorityReady])
                  .catch( (error) => { throw error });
  }

  private keyHandlers: { [key:string]: KeyHandlerFunc } = {

     "account_user": (apiKey: EncryptedKeyData, apiPrivPk: CryptoKey, apiPrivEnc: string) => {
        this.activeUserKey = { data: apiKey, privPk: apiPrivPk, privEnc: apiPrivEnc };
     },
     "account": (apiKey: EncryptedKeyData,  apiPrivPk: CryptoKey, apiPrivEnc: string) => {
        this.activeAccKey = { data: apiKey, privPk: apiPrivPk, privEnc: apiPrivEnc };
     },
     "excollect": (apiKey: EncryptedKeyData, apiPrivPk: CryptoKey, apiPrivEnc: string) => {
        this.activeExcKey = { data: apiKey, privPk: apiPrivPk, privEnc: apiPrivEnc };
     },
  }

  private unlockApiKeys(
    apiKeys: ApiKeys,
    lockPk:  CryptoKey,
    opts:    { verifyKey: boolean } = { verifyKey: false }
  ) {

    const keysReady: Array<Promise<boolean>> = apiKeys.map( (apiKey) => {

      return this.unlockApiKey( apiKey, lockPk, opts.verifyKey );
    });

    return Promise.all(keysReady)
  }

  private unlockApiKey(
    apiKey:    EncryptedKeyData,
    lockPk:    CryptoKey,
    verifyKey: boolean  = false
  ) {

    return _unlockApiKey( apiKey.key_data as string, lockPk, apiKey.owner_id )
      .then( ({ apiPrivPk, apiPrivEnc }) => {
        
         if ( verifyKey === false ) { 
            return { apiPrivPk, apiPrivEnc };
         }

         return this.verifyPublicKeyAndSigner( apiKey )
           .then( () => { 
             return { apiPrivPk, apiPrivEnc } 
           })
      })
      .then(({ apiPrivPk, apiPrivEnc }) => {

         const api = apiKey.context?.api as string;
 
         if ( this.keyHandlers[api] !== undefined ) {
           this.keyHandlers[api]( apiKey, apiPrivPk, apiPrivEnc )
         }

         return true
      });
  }

  /**
   * Decrypt stored API keys returned from login response
   * 
   * @param {string}  keyId 
   * @param {string}  loginPrivEnc 
   * @param {ApiKeys} apiKeys 
   * 
   * @returns {Promise<boolean>}
   */

  public async loadKeyData( 
    userId:       string,
    loginPrivEnc: string,
    apiKeys:      ApiKeys,
  ) {

      this.loginPk = await loadPrivateKey(loginPrivEnc, 'x25519');

      this.userId       = userId;
      this.loginPrivEnc = loginPrivEnc;
      this.apiKeys      = apiKeys;

      return this.unlockApiKeys( apiKeys, this.loginPk );
  }

  public isLoggedIn(): boolean {
    return (this.userId && this.loginPk) ? true : false;
  }

  private buildUserAgent() {

    const axiosInstance = axios.create({
      "baseURL":   this.apiUrl,
      "timeout":   3000,
      "paramsSerializer": function(params) {
        const result = new URLSearchParams(params)
          .toString()
          .replace(/%3A/gi, ':')
          .replace(/,/gi, '%2C');

        return result;
      }
    });

    axiosRetry( axiosInstance, { retries: 0 } );

    axiosInstance.defaults.headers.common['Content-Type'] = 'application/json'; 

    axiosInstance.interceptors.request.use(
      async function ( this: ExCollectClient, config: InternalAxiosRequestConfig ) {

        if ( 'data' in config ) {

          config['data'] = ( config['method']?.toLowerCase() != 'get' ) 
            ? JSON.stringify( config['data'], null ) 
            : '';
        }

        if ( config.headers['X-EXC-Anon'] === '1' ) { 
          return config;
        }

        if ( !this.isLoggedIn() ) {
          throw new Error('Not logged in'); 
        }

        // TODO getRequestOpts(config) function
        // to set signOpts based on api 
        const signOpts = {
          'keyId':      this.activeUserKey?.data.id as string, 
          'pk':         this.activeUserKey?.privPk as CryptoKey,
          'timeOffset': this.timeOffset,
        };

        await signApiRequest( config, signOpts );

        return config; 
      }.bind(this),
      function ( error: AxiosError ) { Promise.reject(error) }
    );

    axiosInstance.interceptors.response.use(
      function (response) { return response; }, 
      function ( error: AxiosError ) { return Promise.reject(error); }
    );

    return axiosInstance;
  }

  /**
   * 
   * @param {ExcRequestConfig} reqCfg 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async request(
    reqCfg: ExcRequestConfig
  ) {

    this.logger.debug('request', reqCfg );

    await this.ready;
    await this.getTimeOffset();

    try {
      /* await here to handle any exception locally. Trades a slight
         performance penalty for consistent error logging in our 
         catch block.
      */
      return await this.userAgent.request(reqCfg);
    }
    catch ( error ) {

      if ( error instanceof AxiosError )  {

        if ( error.response ) {

          this.logger.error( error.response.status, error.response.data);

          const data = error.response.data;

          return Promise.reject({ 
            request_id: data.request_id, 
            error_msg: data.error,
            error_id:  data.error_type_id  
          } as ExcApiError);

        } 
        else if (error.request) {
          // The request was made but no response was received 
          this.logger.error('No Response', error.request);

          return Promise.reject({ 
            request_id: '000000000000000', 
            error_msg: 'No Response',
            error_id:  '500.0'  
          } as ExcApiError);

        } 

        // Something happened in setting up the request that triggered an Error
        this.logger.error('Critical Error', error.message );

        return Promise.reject({ 
          request_id: '000000000000000', 
          error_msg: 'Client Error',
          error_id:  '500.1'  
        } as ExcApiError);

      }
 
      this.logger.error('Unexpected Error', error ); 

      return Promise.reject({ 
        request_id: '000000000000000', 
        error_msg: 'Unknown Error',
        error_id:  '500.2'  
      } as ExcApiError);
    }
  }

  /**
   * @param {string}           url
   * @param {ExcRequestConfig} [params] 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async get( 
    url:     string, 
    params?: ExcRequestConfig 
  ) {

    params ||= {};
    params['url']    = url;
    params['method'] = 'get';

    return this.request(params); 
  }

  /**
   * @param {string}           url
   * @param {ExcRequestData}   data
   * @param {ExcRequestConfig} [params] 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async post(
    url:     string,
    data:    ExcRequestData,
    params?: ExcRequestConfig
  ) {

    params ||= {};
    params['url']    = url;
    params['data']   = data;
    params['method'] = 'post';

    return this.request(params);
  }

  /**
   * @param {string}           url
   * @param {ExcRequestData}   data
   * @param {ExcRequestConfig} [params] 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async put(
    url:     string,
    data:    ExcRequestData,
    params?: ExcRequestConfig
  ) {

    params ||= {};
    params['url']    = url;
    params['data']   = data;
    params['method'] = 'put';

    return this.request(params);
  }

  /**
   * @param {string}           url
   * @param {ExcRequestData}   data
   * @param {ExcRequestConfig} [params] 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async patch( 
    url:     string,
    data:    ExcRequestData,
    params?: ExcRequestConfig
  ) {

    params ||= {};
    params['url']    = url;
    params['data']   = data;
    params['method'] = 'patch';

    return this.request(params);
  } 

  /**
   * @param {string}           url
   * @param {ExcRequestConfig} [params] 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async delete(
    url:     string,
    params?: ExcRequestConfig
  ) {

    params ||= {};
    params['url']    = url;
    params['method'] = 'delete';

    return this.request(params);
  }

  private async getTimeOffset() {

    if ( this.needsTimeOffsetUpdate === false ) {
        return this.timeOffset;
    }

    const ts = getCurrentTimeStamp();

    try {
       const resp = await this.userAgent.request({
         method:  'post',
         url:     '/time_offset',
         data:    { timestamp: ts },
         headers: { 'X-EXC-Anon': '1' }
       });

       this.timeOffset            = resp.data['message']['offset'];
       this.needsTimeOffsetUpdate = false;
    }
    catch ( error ) {
       this.logger.error('Error updating timeoffset: ', error);

       // Fallback to just setting it to zero
       // With needsTimeOffsetUpdate still set to 
       // true the next request will retry setting.
       // the real value.
       this.timeOffset = 0;

       Promise.reject(error);
    }

    return this.timeOffset; 
  }

  /**
   * 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */ 
  public async ping() {

    try {
       const resp = await this.userAgent.request({
         method:  'get',
         url:     '/ping',
         headers: { 'X-EXC-Anon': '1' }
       });

       return resp
    }
    catch ( error ) {
       Promise.reject(error);
    }
  }

  /**
   * 
   * @param {string} code 
   * @param {string} email 
   * @param {string} passphrase 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async activateUser( 
    code:       string,
    email:      string,
    passphrase: string
  ) {

    await this.ready; 

    try {

      const encryptor = await this.buildEncryptor();

      const resp = await this.userAgent.request({
        method:  'post',
        url:     '/account_api/users/activate_user',
        data: {
          edh: {
             "dhk_id":     encryptor.keyId,
             "public_key": await encryptor.getOurPubKeyEncoded()
          },
          code:     code,
          email:    email,
          password: await encryptor.encrypt(passphrase)
        },
        headers: { 'X-EXC-Anon': '1' }
      });

      const keyData = resp.data['message']['data']['login_key'] as LoginKeyData;

      await this.setApiKeyData(keyData, passphrase);

      return resp;
    }
    catch ( error ) {
      return this.catchClientError(error, 'Activation Failed','400.2')
    }
  }

  /**
   * 
   * @param {string} email 
   * @param {string} passphrase 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */
  public async logIn( 
    email:      string,
    passphrase: string
  ) {

    await this.ready; 

    try {

      const encryptor = await this.buildEncryptor();

      const resp = await this.userAgent.request({
        method:  'post',
        url:     '/account_api/users/login_user',
        data: {
          email: email,
          edh: {
             "dhk_id":     encryptor.keyId,
             "public_key": await encryptor.getOurPubKeyEncoded()
          },
          password: await encryptor.encrypt(passphrase)
        },
        headers: { 'X-EXC-Anon': '1' }
      });

      const keyData = resp.data['message']['data']['login_key'] as LoginKeyData;

      await this.setApiKeyData(keyData, passphrase);

      return resp;
    }
    catch ( error ) {
      return this.catchClientError(error, 'Login Failed','400.3')
    }
  } 

  /**
   * 
   * @param {string} oldPassphrase 
   * @param {string} newPassphrase 
   * 
   * @returns {Promise<AxiosResponse<any,any>|ExcApiError>} 
   */ 
  public async changePassword( 
    oldPassphrase: string,
    newPassphrase: string
  ) {

    await this.ready; 

    try {

      const encryptor = await this.buildEncryptor();

      const resp = await this.userAgent.request({
        method:  'post',
        url:     '/account_api/users/change_password',
        data: {
          edh: {
             "dhk_id":     encryptor.keyId,
             "public_key": await encryptor.getOurPubKeyEncoded()
          },
          old_password: await encryptor.encrypt(oldPassphrase),
          new_password: await encryptor.encrypt(newPassphrase)
        },
      });

      const keyData = resp.data['message']['data']['login_key'] as LoginKeyData;

      await this.setApiKeyData(keyData, newPassphrase);

      return resp;
    }
    catch ( error ) {
      return this.catchClientError(error, 'Pasword Change Failed','404.4')
   }
  } 

  private catchClientError( 
      error:          any,
      errorMsg:       string,
      defaultErrorId: string
  ) {

    this.logger.error(error);

    /* We already have a rejected Promise from this.request() */
    if ( error instanceof Promise )  {
      return error;
    }

    /* We have an error from this.userAgent.request() */
    if ( error instanceof AxiosError 
         && error.response !== undefined
    )  {

       return Promise.reject({ 
         request_id: error.response.data['request_id'], 
         error_msg:  errorMsg,
         error_id:   error.response.data['error_type_id']  
       } as ExcApiError);
    }

    /* some other error occured around making a request */
    return Promise.reject({ 
      request_id: '000000000', 
      error_msg: errorMsg,
      error_id:  defaultErrorId  
    } as ExcApiError);
  }

  private async setApiKeyData( 
    keyData:    LoginKeyData,
    passphrase: string
  ) {
    await this.verifyPublicKeyAndSigner( keyData );

    const { 
      loginPrivPk, 
      loginPrivEnc 
    } = await unlockLoginKey( 
      keyData.key_data as string, 
      passphrase, 
      keyData.owner_id
    )

    this.loginPk = loginPrivPk;

    await this.unlockApiKeys( keyData.api_keys, loginPrivPk, { verifyKey: true } );

    this.userId       = keyData.owner_id;
    this.loginPrivEnc = loginPrivEnc;
    this.apiKeys      = keyData.api_keys;
  }

  private async buildEncryptor() {

    const { privateKey: ourPrivatePk }    = await createX25519Keys() as CryptoKeyPair;
    const { theirPublicPk, theirKeyData } = await this.fetchServerDhKey() as { theirPublicPk: CryptoKey, theirKeyData: PubKeyData };

    return new Encryptor( ourPrivatePk, theirKeyData.id, theirPublicPk );
  }

  private async fetchServerDhKey() {

    try {
      const resp = await this.userAgent.request({ 
        method:  'get',
        url:     '/account_api/users/login_dh_key',
        headers: { 'X-EXC-Anon': '1' }
      });

      const theirKeyData = resp.data['message'] as PubKeyData;

      await this.verifyPublicKeyAndSigner( theirKeyData );

      const theirPublicPk = await loadPublicKey( theirKeyData['public_key'], 'x25519' );

      return { theirPublicPk, theirKeyData };
    }
    catch ( error ) {
      this.logger.error('Error fetching server ECDH key: ', error);

      Promise.reject(error);
    }
  } 

  /**
   * 
   * @param {ApiKeys}  keys 
   * 
   * @returns {Promise<Array<bool>>} 
   */
  public async addApiKeys(
    keys: ApiKeys 
  ) {
    await this.ready;

    if ( !this.isLoggedIn() ) {
      throw new Error('Not logged in');
    } 

    const keyPromises = keys.map( keyData => {

      this.apiKeys?.push(keyData);

      return this.unlockApiKey(keyData, this.loginPk as CryptoKey, true )
    });

    return Promise.all(keyPromises); 
  }

  /**
   * 
   * @param {CommandInstance} instance 
   * 
   * @returns {{ signature: string, keyId: string, jobSigs: { [jobId: string]: string } }} 
   */
  public async signCommandInstance(
    instance: CommandInstance
  ) {
    await this.ready;

    if ( !this.isLoggedIn() ) {
      throw new Error('Not logged in');
    } 

    return _signCommandInstance( 
      instance, 
      this.activeExcKey?.data.id as string, 
      this.activeExcKey?.privPk as CryptoKey
    );
  }

  public async createSignedDhKey() {
    await this.ready;

    if ( !this.isLoggedIn() ) {
      throw new Error('Not logged in');
    } 

    const excKeyId = this.activeExcKey?.data.id;
    const excPk    = this.activeExcKey?.privPk

    const { dhPubEnc, sigEnc, privateKey } = await _createSignedDhKey( excPk as CryptoKey );

    return { excKeyId, dhPubEnc, sigEnc, privateKey }
  }

  public async verifyPublicKeyAndSigner(
    keyData: PubKeyData,
   ) {

    return _verifyPublicKeyAndSigner( keyData, this.rootAuthorityPk );
  }


  public async verifySignedDhKey(
    dhPubEnc:  string,
    signature: string,
    pubPk:     CryptoKey
  ) {
    await this.ready;

    if ( !this.isLoggedIn() ) {
      throw new Error('Not logged in');
    } 

    const excPk = this.activeExcKey?.privPk

    return _verifySignedDhKey( dhPubEnc, signature, pubPk );
  }

  public async getDhSecret(
    dhPubEnc:  string,
    privPk:    CryptoKey
  ) {

    const pubPk = await loadPublicKey( dhPubEnc, 'x25519' ); 

    return deriveSecret( privPk, pubPk );
  }

  public async decryptMessage(
    cipher:  string,
    secret:  ArrayBuffer 
  ) {

    return eceDecrypt2( cipher, secret );
  }

  public async encryptMessage(
    cipher:  string,
    secret:  ArrayBuffer 
  ) {

    return eceEncrypt2( cipher, secret );
  }

  public logOut() {
    this.userId        = undefined;
    this.apiKeys       = undefined;
    this.loginPrivEnc  = undefined;
    this.loginPk       = undefined;
    this.activeUserKey = undefined;
    this.activeAccKey  = undefined;
    this.activeExcKey  = undefined;
  }  

  public async createKeyChangeAuthorization( 
    userUuid:   string,
    context:    string,
    contextId:  string,
    privileged: number = 0,
    updates:    { status? : string } = {},
  ) {

    await this.ready;
 
    const authorizorKey = context == 'site'    ? this.activeExcKey :
                          context == 'account' ? this.activeAccKey : 
                          ( () => { throw "Invalid Context" } )();

    const authorizorId = authorizorKey?.data.owner_id as string; 
    const authorizorPk = authorizorKey?.privPk        as CryptoKey; 
 
    return _createKeyChangeAuthorization(
              authorizorId, authorizorPk, userUuid, context, contextId, privileged, updates );
  }

}
