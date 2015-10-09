var AuthLib = require('../lib');
var express = require('express');
var bodyParser = require('body-parser');
var http = require('http');
var request = require('request-promise');
var RestStub = require('svp-reststub');
var lodash = require('lodash');

var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');
var portFinder = require('svp-portfinder');
var UserStore = require('./lib/simpleUserStore');

describe('google', () => {
  var app = express();
  var server = http.createServer(app);
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());

  var auth, googleLogin, serviceUrl, stubUrl;
  var log = getLogger('google');
  var stub = new RestStub(log);
  var users = new UserStore();

  before(() => {
    return stub.start()
      .then((url) => {
        stubUrl = url;

        var opts = users.createAuthLibOpts();
        opts.log = log;
        opts.secret = 'google tests';
        auth = new AuthLib.Auth(opts);

        var googOpts = {
          clientIDs: ['123456'],
          authHost: stubUrl,
        };
        googleLogin = new AuthLib.Logins.google('google', auth, googOpts);
        auth.initExpress(app);
        var startServer =  portFinder()
          .then((port) => {
            serviceUrl = 'http://localhost:' + port;
            return new Promise((resolve, reject) => {
              server.listen(port);
              server.on('listening', resolve);
              server.on('error', reject);
            });
          });

        var user = {
          id: 'google:1234',
          google: '1234',
          name: 'Jane Doe',
          email: 'doe@example.com'
        };
        var initUser = users.addUser(auth, user);

        return Promise.all([startServer, initUser]);
      });
  });

  it('login existing google user', () => {
    setGoogleAuthStubs('1234', '123456', {});
    var reqOpts = {
      uri: serviceUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 'foo'}
    };
    return request(reqOpts)
      .then((data) => {
        log.info({data: data}, 'google login');
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 'google:1234');
        return users.lookupAccount({id: data.id});
      })
      .then((user) => {
        log.info({user: user}, 'found google login user');
        user.should.have.property('picture', 'http://example.com/image/1234.jpg');
        user.should.have.property('email', 'doe@example.com');
      });
  });

  it('login again', () => {
    setGoogleAuthStubs('1234', '123456', {});
    var reqOpts = {
      uri: serviceUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 'foo'}
    };
    return request(reqOpts);
  });

  it('login picks up changed name, email', () => {
    setGoogleAuthStubs('1234', '123456', {name: 'John Doe', email: 'john@example.com'});
    var reqOpts = {
      uri: serviceUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 'foo'}
    };
    return request(reqOpts)
      .then((data) => {
        return users.lookupAccount({id: data.id});
      })
      .then((user) => {
        user.should.have.property('name', 'John Doe');
        user.should.have.property('email', 'john@example.com');
      });
  });

  it('bad tokens cannot login', () => {
    stub.setResponse('tokenInfo', '/oauth2/v1/tokenInfo', {error: 'invalid token'});
    var reqOpts = {
      uri: serviceUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 'bar'},
      simple: false,
      resolveWithFullResponse: true
    };
    return request(reqOpts)
      .then((res) => {
        res.statusCode.should.equal(401);
        res.should.have.deep.property('body.message', 'Unauthorized');
      });
  });

  it('bad clientid cannot login', () => {
    setGoogleAuthStubs('1234', 'notmatch', {name: 'John Doe', email: 'john@example.com'});
    var reqOpts = {
      uri: serviceUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 'bar'},
      simple: false,
      resolveWithFullResponse: true
    };
    return request(reqOpts)
      .then((res) => {
        res.statusCode.should.equal(401);
        res.should.have.deep.property('body.message', 'Unauthorized');
      });
  });

  it('without clientids; bad clientid allowed to login', () => {
    setGoogleAuthStubs('1234', 'notmatch', {name: 'John Doe', email: 'john@example.com'});
    // temporarily remove clientIDs from Google Login
    var savedIDs = googleLogin.clientIDs;
    googleLogin.clientIDs = [];
    var reqOpts = {
      uri: serviceUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 'bar'},
    };
    return request(reqOpts)
      .then((data) => {
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 'google:1234');
        googleLogin.clientIDs = savedIDs;
      });
  });

  it('construct with default options', () => {
    new AuthLib.Logins.google('altgoogle', auth);
  });

  function setGoogleAuthStubs(userId, issuedTo, userOverrides) {
    var tokenInfo = {
      audience: issuedTo,
      issued_to: issuedTo,
      user_id: userId,
      scope: 'profile',
      expires_in: 3600
    };
    stub.setResponse('tokenInfo', '/oauth2/v1/tokenInfo', tokenInfo);
    var userInfo = {
      id: userId,
      name: 'Jane Doe',
      picture: 'http://example.com/image/' + userId + '.jpg',
      email: 'doe@example.com',
      // the following fields are in google responses; but we do not use them
      //given_name: 'Jane',
      //family_name: 'Doe',
      //link: 'http://example.com/profile/' + userId,
      //gender: 'female',
      //locale: 'en'
    };
    userInfo = lodash.extend(userInfo, userOverrides);
    stub.setResponse('userInfo', '/oauth2/v1/userInfo', userInfo);
  }
});
