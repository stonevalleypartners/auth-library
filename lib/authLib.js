'use strict';

var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var lodash = require('lodash');

var passport = require('passport');
var bearerStrategy = require('passport-http-bearer');

/**
 * Instantiates the authentication library
 */
class AuthLib {
  /**
   * AuthLib constructor
   * @param {object} opts - options
   * @param {integer} [opts.tokenDuration=3600] - duration of the accessToken in seconds
   * @param {string} opts.secret - secret used when encrypting tokens
   * @param {integer} [opts.maxRefreshTokens=5] - maximum number of refresh tokens per user
   * @param {function} opts.lookupAccount - lookup an account by id, email, or external account id
   * @param {function} [opts.registerExternalAccount] - registers a user coming from external account
   * @param {function} opts.updateTokens - updates refresh tokens associated with an account
   */
  constructor(opts) {
    this.logins = [];
    this.log = opts.log;
    this.opts = opts;
    this.opts.tokenDuration = this.opts.tokenDuration || 3600;
    if(!this.opts.secret) throw new Error('opts.secret required');
    if(!lodash.isNumber(this.opts.maxRefreshTokens)) {
      this.opts.maxRefreshTokens = 5;
    }
    if(!this.opts.lookupAccount) throw new Error('opts.lookupAccount required');
    if(!this.opts.updateTokens) throw new Error('opts.updateTokens required');

    if(!this.log) throw new Error('opts.log required');
  }

  /**
   * encrypt an object
   * @param obj - an object to serialize and encrypt
   * @returns {string} a base64 string of the input obj
   */
  encryptObject(obj) {
    var buf = new Buffer(this.opts.secret);
    var cipher = crypto.createCipher('aes-256-cbc', buf);
    var encodedText = cipher.update(JSON.stringify(obj), 'utf8', 'base64');
    encodedText += cipher.final('base64');
    encodedText = encodedText.replace(/\+/g, '-');
    encodedText = encodedText.replace(/\//g, '_');
    return encodedText;
  }

  /**
   * decrypt an object
   * @param str - an encrypted serialized object
   * @returns {object} the decrypted object
   */
  decryptObject(str) {
    str = str.replace(/-/g, '+');
    str = str.replace(/_/g, '/');

    var buf = new Buffer(this.opts.secret);
    var decipher = crypto.createDecipher('aes-256-cbc', buf);
    var plainText;
    try {
      plainText = decipher.update(str, 'base64', 'utf8');
      plainText += decipher.final('utf8');
    } catch(err) {
      throw new Error('unable to decrypt object');
    }

    var obj;
    try {
      obj = JSON.parse(plainText);
    } catch(err) {
      throw new Error('cannot convert to object');
    }
    return obj;
  }

  getAccessToken(user, type) {
    var jwtOpts = {expiresIn: this.opts.tokenDuration, algorithm: 'HS256'};
    var accessToken = jwt.sign({id: user.id}, this.opts.secret, jwtOpts);
    var token = {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: this.opts.tokenDuration,
      id: user.id,
    };

    if(type === 'offline' && this.opts.maxRefreshTokens > 0) {
      return this.getRefreshToken(user)
        .then((refreshToken) => {
          token.refresh_token = refreshToken;
          return token;
        });
    }

    return Promise.resolve(token);
  }

  getRefreshToken(user) {
    var refreshObj = {
      i: user.id,
      n: Date.now(),
    };
    var refreshToken = this.encryptObject(refreshObj);
    user.auth.refreshTokens.unshift(refreshToken);
    user.auth.refreshTokens = lodash.take(user.auth.refreshTokens, this.opts.maxRefreshTokens);
    return user.save()
      .then(() => refreshToken);
  }

  initExpress(app) {
    var validator = this._validateAccessToken.bind(this);
    var opts = {passReqToCallback: true};
    passport.use(new bearerStrategy(opts, validator));
    app.use(passport.initialize());

    if(this.opts.maxRefreshTokens > 0) {
      app.post('/auth/token', this.verifyToken.bind(this));
    }

    lodash.forEach(this.logins, (login) => {
      this.log.error({type: login.constructor.name}, 'configuring route...');
      login.configureRoute(app);
    });
  }

  addAuthMiddleware() {
    return (req, res, next) => {
      passport.authenticate('bearer', {session: false})(req, res, next);
    };
  }

  verifyToken(req, res) {
    if(!req.body.refresh_token) return this._sendFail(res, 'missing token');
    if(req.body.grant_type !== 'refresh_token') return this._sendFail(res, 'unsupported grant type');

    Promise.resolve(this.decryptObject(req.body.refresh_token))
      .then((token) => this.opts.lookupAccount({id: token.i}))
      .then((user) => {
        if(!lodash.contains(user.auth.refreshTokens, req.body.refresh_token)) {
          throw new Error('refresh token not in users refresh set');
        }
        return this.getAccessToken(user, req.body.access_type)
          .then(token => res.json(token));
      })
      .catch((e) => {
        this.log.info({err: e}, 'verify token failed');
        return this._sendFail(res, 'Unauthorized');
      });
  }

  _sendFail(res, msg) {
    return Promise.resolve(res.status(401).json({message: msg}));
  }

  _validateAccessToken(req, token, done) {
    var obj;
    try {
      obj = jwt.verify(token, this.opts.secret, {algorithms: ['HS256']});
    } catch(err) {
      this.log.info({err: err}, 'token err');
      // null/undefined user in done() is handled as unauthenticated by passport
      return done(null, null);
    }
    return done(null, {id: obj.id});
  }
}

module.exports = AuthLib;
