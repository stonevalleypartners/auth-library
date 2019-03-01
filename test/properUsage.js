var Test = require('./lib/test.js');

var AuthLib = require('../lib');
var request = require('request-promise');
var lodash = require('lodash');

describe('proper usage', () => {
  var test = new Test('usage');
  var auth, local, google;

  before(() => {
    test.createGoogleAuthStub()
      .then(() => test.createExpressServer())
      .then(() => {
        var opts = {
          secret: 'proper usage',
          log: test.log,
          lookupAccount: () => Promise.resolve({name: 'Jane Doe', id: 12345}),
          updateTokens: lodash.noop,
        };
        auth = new AuthLib.Auth(opts);
        local = new AuthLib.Logins.local('local', auth);
        var googOpts = {authHost: test.google.url};
        google = new AuthLib.Logins.google('google', auth, googOpts);
        auth.initExpress(test.app);
        test.setGoogleAuthStubs('12345', undefined, {});
      });
  });

  after(() => {
    test.closeExpressServer();
    test.closeGoogleAuthStub();
  });

  it('local login fails', () => {
    var reqOpts = {
      uri: test.appUrl + '/auth/local/verify',
      method: 'post',
      json: {id: 12345, password: 'secret'},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((resp) => {
        test.log.debug({resp: resp}, 'usage; local login fails with bad user object');
        resp.statusCode.should.equal(401);
        resp.should.have.nested.property('body.message', 'Unauthorized');
      });
  });

  it('google login fails', () => {
    var reqOpts = {
      uri: test.appUrl + '/auth/google/verify',
      method: 'post',
      json: {accessToken: 12345},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((resp) => {
        test.log.debug({resp: resp}, 'usage; google login fails with bad user object');
        resp.statusCode.should.equal(401);
        resp.should.have.nested.property('body.message', 'Unauthorized');
      });
  });
});
