'use strict';
var lodash = require('lodash');
var Auth = require('../lib').Auth;

var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');

var log = getLogger('(en|de)crypt');
var opts = {
  secret: '(en|de)crypt example',
  log: log,
  lookupAccount: lodash.noop,
  updateTokens: lodash.noop,
  updateAccount: lodash.noop,
};
var auth = new Auth(opts);

describe('encryptHelpers', () => {
  var original = {foo: 123, bar: 'abc'};
  var encryptedString;

  it('encrypt object', () => {
    encryptedString = auth.encryptObject(original);
  });

  it('decrypt object', () => {
    var decrypted = auth.decryptObject(encryptedString);
    decrypted.should.deep.equal(original);
  });
});
