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
   * @param {integer} [opts.refreshDuration=0] - duration of the refreshToken in seconds
   * @param {string} opts.secret - secret used when encrypting tokens
   * @param {integer} [opts.maxRefreshTokens=5] - maximum number of refresh tokens per user
   * @param {function} opts.lookupAccount - lookup an account by id, email, or external account id
   * @param {function} [opts.registerExternalAccount] - registers a user coming from external account
   * @param {function} opts.updateTokens - updates refresh tokens associated with an account
   * @param {function} opts.getExtendedJWTFields - customize JWT with additional fields
   */
  constructor(opts) {
    this.logins = [];
    this.log = opts.log;
    this.opts = opts;
    this.opts.tokenDuration = this.opts.tokenDuration || 3600;
    this.opts.refreshDuration = this.opts.refreshDuration || 0;
    if(!this.opts.secret) throw new Error('opts.secret required');
    this.opts.maxRefreshTokens = this.opts.maxRefreshTokens || 5;
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
    const jwtFields = (this.opts.getExtendedJWTFields) ? this.opts.getExtendedJWTFields(user) : {}
    jwtFields.id = user.id

    var jwtOpts = {expiresIn: this.opts.tokenDuration, algorithm: 'HS256'};
    var accessToken = jwt.sign(jwtFields, this.opts.secret, jwtOpts);
    var token = {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: this.opts.tokenDuration,
      id: user.id,
    };

    if(type === 'offline') {
      var refreshOpts = {algorithm: 'HS256', issuer: 'authlib'};
      if(this.opts.refreshDuration) {
        refreshOpts.expiresIn =  this.opts.refreshDuration;
      }
      token.refresh_token = jwt.sign(jwtFields, this.opts.secret, refreshOpts);
      this.opts.updateTokens(user, token.refresh_token);
    }

    return token;
  }

  initExpress(app) {
    var validator = this._validateAccessToken.bind(this);
    var opts = {passReqToCallback: true};
    passport.use(new bearerStrategy(opts, validator)); // jshint ignore:line
    app.use(passport.initialize());

    lodash.forEach(this.logins, (login) => {
      this.log.info({type: login.constructor.name}, 'configuring route...');
      login.configureRoute(app);
    });
  }

  addAuthMiddleware() {
    return (req, res, next) => {
      passport.authenticate('bearer', {session: false})(req, res, next);
    };
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
    return done(null, obj);
  }
}

module.exports = AuthLib;
