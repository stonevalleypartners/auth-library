var Test = require('./lib/test.js');

var AuthLib = require('../lib');
var request = require('request-promise');

describe('refresh tokens', () => {
  var test = new Test('refresh');
  var auth;

  before(() => {
    return test.createExpressServer()
      .then(() => {
        var opts = test.users.createAuthLibOpts();
        opts.log = test.log;
        opts.secret = 'refresh';
        opts.maxRefreshTokens = 2;
        auth = new AuthLib.Auth(opts);
        new AuthLib.Logins.local('local', auth);
        auth.initExpress(test.app);
        return test.users.addUser({id: 123, password: 'sekret', email: 'foo@svp'});
      });
  });

  it('user should not have a refresh token', () => {
    test.users.lookupAccount({id: 123})
      .then((user) => {
        user.should.have.deep.property('auth.refreshTokens');
        user.auth.refreshTokens.length.should.equal(0);
      });
  });

  var refreshToken;
  it('get refresh token', () => {
    return _getRefreshToken()
      .then((token) => {
        refreshToken = token;
      })
      .then(() => test.users.lookupAccount({id: 123}))
      .then((user) => {
        user.should.have.deep.property('auth.refreshTokens');
        user.auth.refreshTokens.length.should.equal(1);
        refreshToken.should.equal(user.auth.refreshTokens[0]);
      });
  });

  it('can obtain access token from refresh token', () => {
    var reqOpts = {
      uri: test.appUrl + '/auth/token',
      method: 'post',
      json: {refresh_token: refreshToken, grant_type: 'refresh_token'},
    };
    return request(reqOpts)
      .then((data) => {
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 123);
        data.should.not.have.property('refresh_token');
      })
      .then(() => test.users.lookupAccount({id: 123}))
      .then((user) => {
        user.should.have.deep.property('auth.refreshTokens');
        user.auth.refreshTokens.length.should.equal(1);
      });
  });

  it('/auth/token requires refresh_token', () => {
    var reqOpts = {
      uri: test.appUrl + '/auth/token',
      method: 'post',
      json: {opps_token: refreshToken, grant_type: 'refresh_token'},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((res) => {
        res.statusCode.should.equal(401);
        res.should.have.deep.property('body.message', 'missing token');
      });
  });

  it('/auth/token with unsupported grant_type', () => {
    var reqOpts = {
      uri: test.appUrl + '/auth/token',
      method: 'post',
      json: {refresh_token: refreshToken, grant_type: 'oops'},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((res) => {
        res.statusCode.should.equal(401);
        res.should.have.deep.property('body.message', 'unsupported grant type');
      });
  });

  it('get 2nd refresh token', () => {
    var secondToken;
    return _getRefreshToken()
      .then((token) => {
        secondToken = token;
      })
      .then(() => test.users.lookupAccount({id: 123}))
      .then((user) => {
        user.should.have.deep.property('auth.refreshTokens');
        user.auth.refreshTokens.length.should.equal(2);
        secondToken.should.equal(user.auth.refreshTokens[0]);
        refreshToken.should.equal(user.auth.refreshTokens[1]);
      });
  });

  it('get 3rd refresh token', () => {
    var thirdToken;
    return _getRefreshToken()
      .then((token) => {
        thirdToken = token;
      })
      .then(() => test.users.lookupAccount({id: 123}))
      .then((user) => {
        user.should.have.deep.property('auth.refreshTokens');
        user.auth.refreshTokens.length.should.equal(2);
        thirdToken.should.equal(user.auth.refreshTokens[0]);
        refreshToken.should.not.equal(user.auth.refreshTokens[1]);
      });
  });

  it('/auth/token with refresh token not in users list of refresh tokens', () => {
    var reqOpts = {
      uri: test.appUrl + '/auth/token',
      method: 'post',
      json: {refresh_token: refreshToken, grant_type: 'refresh_token'},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((res) => {
        res.statusCode.should.equal(401);
        res.should.have.deep.property('body.message', 'Unauthorized');
      });
  });

  function _getRefreshToken() {
    var reqOpts = {
      uri: test.appUrl + '/auth/local/verify',
      method: 'post',
      json: {id: 123, password: 'sekret', access_type: 'offline'},
    };
    return request(reqOpts)
      .then((data) => {
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 123);
        data.should.have.property('refresh_token');
        return data.refresh_token;
      });
  }
});
