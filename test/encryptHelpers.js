var lodash = require('lodash');
var crypto = require('crypto');
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

  it('decrypt random string should fail', () => {
    return new Promise((resolve) => {
      resolve(auth.decryptObject('has not been encrypted'));
    })
    .should.eventually.be.rejectedWith('unable to decrypt object');
  });

  it('decrypt non-object should fail', () => {
    // manually construct encrypted string
    var buf = new Buffer(opts.secret);
    var cipher = crypto.createCipher('aes-256-cbc', buf);
    var encodedText = cipher.update('a string and not an object', 'utf8', 'base64');
    encodedText += cipher.final('base64');
    encodedText = encodedText.replace(/\+/g, '-');
    encodedText = encodedText.replace(/\//g, '_');
    return new Promise((resolve) => {
      resolve(auth.decryptObject(encodedText));
    })
    .should.eventually.be.rejectedWith('cannot convert to object');
  });
});
