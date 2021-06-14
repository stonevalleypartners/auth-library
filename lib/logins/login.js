'use strict';

const crypto = require('crypto');
const { fromKeyLike } = require('jose/jwk/from_key_like');

/**
 * abstract base class for logging in
 */
class Login {
  /**
    constructor
    @param loginName - name of the login will be used to construct route
    @param authLib - authentication library to which this login method will be added
  */
  constructor(loginName, authLib) {
    this.loginName = loginName;
    this.authLib = authLib;

    this.authLib.logins.push(this);
  }

  /**
    configures express routes for handling login
    @param app - express app
  */
  configureRoute(app) {
    const storeIssuer = (req, res, next) => {
      const host = req.headers['x-forwarded-host'] || req.headers.host;
      res.locals.issuer = `${req.protocol}://${host}/auth/${this.loginName}`;
      next();
    };
    // configure username/password route
    var v = this.verify.bind(this);
    this.authLib.log.info('adding route to app');
    const loginRoute = '/auth/' + this.loginName + '/verify';
    app.use(loginRoute, storeIssuer);
    app.post(loginRoute, v);

    // configure refreshtoken route
    if(this.verifyRefresh) {
      this.authLib.log.info('configuring refresh token route');
      var vr = this.verifyRefresh.bind(this);
      const refreshRoute = '/auth/' + this.loginName + '/token';
      app.use(refreshRoute, storeIssuer);
      app.post(refreshRoute, vr);
    }

    // configure well known routes if signing algorithm is RS256
    if(this.authLib.opts.signAlg === 'RS256') {
      this.authLib.log.info('adding openid + jwks routes');
      app.get(
        '/auth/' + this.loginName + '/.well-known/openid-configuration',
        this.openIDConfiguration.bind(this)
      );
      app.get(
        '/auth/' + this.loginName + '/.well-known/jwks.json',
        this.getKeySet.bind(this)
      );
    }
  }

  /**
    verifies a login attempt
  */
  verify() {
    return Promise.reject(new Error('Subclass must override verify() method'));
  }

  /**
    send openIDConfiguration
  */
  openIDConfiguration(req, res) {
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return res.json({
      jwks_uri: `${req.protocol}://${host}/auth/${this.loginName}/.well-known/jwks.json`,
    });
  }

  /**
    get the jsonwebtoken keyset for RS256 public key

    clients use this API to obtain the public key which allows them to verify that
    the entity using this authLibrary generated the tokens
  */
  getKeySet(req, res) {
    const key = crypto.createPublicKey(this.authLib.opts.keys.public);
    fromKeyLike(key).then((publicJwk) => {
      publicJwk.alg = 'RS256';
      publicJwk.use = 'sig';
      publicJwk.kid = this.authLib.kid;
      return res.json({
        keys: [publicJwk],
      });
    });
  }

  /**
    send response to login the user (verify succeeded)
    @param accessType - offline 
    @param res - http response
    @param user - user record for login
  */
  sendSuccess(accessType, res, user) {
    var token = this.authLib.getAccessToken(user, accessType, res.locals.issuer);
    return res.json(token);
  }

  /**
    send fail response to login the user
    @param res - http response
  */
  sendFail(res) {
    return res.status(401).json({message: 'Unauthorized'});
  }
}

module.exports = Login;
