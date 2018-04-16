var AuthLib = require('../lib');
var express = require('express');
var bodyParser = require('body-parser');
var http = require('http');
var request = require('request-promise');
var errors = require('request-promise/errors');
var jwt = require('jsonwebtoken');

var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');
var portFinder = require('svp-portfinder');
var UserStore = require('./lib/simpleUserStore');

// Uses local login methods to test refresh tokens

describe('Refresh', () => {
  var app = express();
  var server = http.createServer(app);
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());

  var auth, url;
  var authSecret = 'testAuthLib';
  var log = getLogger('refresh');
  
  var users = new UserStore();

  it('create authLib', () => {
    var opts = users.createAuthLibOpts();
    opts.log = log;
    opts.secret = authSecret;
    auth = new AuthLib.Auth(opts);
    new AuthLib.Logins.local('local', auth);
    auth.initExpress(app);
    return portFinder()
      .then((port) => {
        url = 'http://localhost:' + port;
        return new Promise((resolve, reject) => {
          server.listen(port);
          server.on('listening', resolve);
          server.on('error', reject);
        });
      });
  });

  it('initialize users', () => {
    return users.addUser({id: 123, password: 'secret', email: 'foo@svp'})
      .then(() => {
        return users.addUser({id: 'abc', password: 'sekret', email: 'bar@svp'});
      });
  });

  var refreshToken;
  it('login user, request refresh token', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 123, password: 'secret', access_type: 'offline'},
    };
    log.error({data: reqOpts}, 'request opts');
    return request(reqOpts)
      .then((data) => {
        log.info({token: data}, 'local login user by id number');
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 123);
        data.should.have.property('refresh_token');
        refreshToken = data.refresh_token;
      });
  });

  it('can obtain access_token via refresh_token', () => {
    var reqOpts = {
      uri: url + '/auth/local/token',
      method: 'post',
      json: {refresh_token: refreshToken},
    };
    return request(reqOpts)
      .then((data) => {
        log.info({token: data}, 'local login user by refresh token');
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 123);
        data.should.not.have.property('refresh_token');
      });
  });

  it('login with invalid refresh token', () => {
    var reqOpts = {
      uri: url + '/auth/local/token',
      method: 'post',
      json: {refresh_token: 'bogus'},
    };
    return request(reqOpts)
      .then(() => {
        throw new Error('login succeeded with invalid refresh token');
      })
      .catch(errors.StatusCodeError, (data) => {
        log.info({token: data}, 'attempted login by an invalid refresh token');
        data.should.have.property('name', 'StatusCodeError');
        data.should.have.property('statusCode', 401);
        data.should.not.have.property('access_token');
        data.should.not.have.property('refresh_token');
      });
  });

  it('login with valid jwt, but invalid user', () => {
    var rt = jwt.sign({id: 'foobar'}, authSecret, {algorithm: 'HS256', issuer: 'authlib'});
    var reqOpts = {
      uri: url + '/auth/local/token',
      method: 'post',
      json: {refresh_token: rt},
    };
    return request(reqOpts)
      .then(() => {
        throw new Error('login succeeded with valid jwt, but invalid user');
      })
      .catch(errors.StatusCodeError, (data) => {
        log.info({token: data}, 'attempted login with valid jwt but unknown refresh');
        data.should.have.property('name', 'StatusCodeError');
        data.should.have.property('statusCode', 401);
        data.should.not.have.property('access_token');
        data.should.not.have.property('refresh_token');
      });
  });

  it('login with valid jwt, but unknown refresh token', () => {
    var rt = jwt.sign({id: 123}, authSecret, {algorithm: 'HS256', issuer: 'testing'});
    var reqOpts = {
      uri: url + '/auth/local/token',
      method: 'post',
      json: {refresh_token: rt},
    };
    return request(reqOpts)
      .then(() => {
        throw new Error('login succeeded with valid jwt, but unknown refresh token');
      })
      .catch(errors.StatusCodeError, (data) => {
        log.info({token: data}, 'attempted login with valid jwt but unknown refresh');
        data.should.have.property('name', 'StatusCodeError');
        data.should.have.property('statusCode', 401);
        data.should.not.have.property('access_token');
        data.should.not.have.property('refresh_token');
      });
  });

  after(() => {
    server.close();
  });
});


