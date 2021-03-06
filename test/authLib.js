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
    };
    authLib = new AuthLib.Auth(opts);
  });

  it('accesstoken', () => {
    var token = authLib.getAccessToken({id: '1111'}, 'bearer');
    log.info({token: token}, 'bearer token');
  });

});
