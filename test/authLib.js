var AuthLib = require('../lib');
var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var lodash = require('lodash');
var getLogger = require('./lib/getLogger');

describe('AuthLib', () => {
  var authLib;
  var log = getLogger('authLib');

  it('instantiate object', () => {
    var opts = {
      log: log,
      secret: 'testAuthLib',
      lookupAccount: lodash.noop,
      updateTokens: lodash.noop,
      updateAccount: lodash.noop,
    };
    authLib = new AuthLib.Auth(opts);
  });

  it('accesstoken', () => {
    var token = authLib.getAccessToken({id: '1111'}, 'bearer');
    log.info({token: token}, 'bearer token');
  });

  it('hashed password', () => {
    return authLib.getHashedPassword('secret')
      .then((hash) => {
        log.info({hash: hash}, 'hashed password');
      });
  });
});
