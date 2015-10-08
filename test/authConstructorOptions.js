var lodash = require('lodash');
var AuthLib = require('../lib');
var Auth = AuthLib.Auth;

var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');

var log = getLogger('constructor');
var allOpts = {
  log: log,
  secret: 'auth constructor tests',
  tokenDuration: 1800,
  maxRefreshTokens: 2,
  lookupAccount: lodash.noop,
  registerExternalAccount: lodash.noop,
  updateTokens: lodash.noop,
  updateAccount: lodash.noop,
};

describe('auth constructor options', () => {
  it('valid construction with all options specified', () => {
    var a = new Auth(allOpts);
    a.opts.tokenDuration.should.equal(1800);
    a.opts.maxRefreshTokens.should.equal(2);
  });

  it('valid construction using tokenDuration default', () => {
    var opts = lodash.clone(allOpts);
    delete opts.tokenDuration;

    var a = new Auth(opts);
    a.opts.tokenDuration.should.equal(3600);
    a.opts.maxRefreshTokens.should.equal(2);
  });

  it('valid construction using maxRefreshTokens default', () => {
    var opts = lodash.clone(allOpts);
    delete opts.maxRefreshTokens;

    var a = new Auth(opts);
    a.opts.tokenDuration.should.equal(1800);
    a.opts.maxRefreshTokens.should.equal(5);
  });

  it('invalid construction missing secret', () => {
    var opts = lodash.clone(allOpts);
    delete opts.secret;

    return new Promise((resolve) => {
      resolve(new Auth(opts));
    })
    .should.eventually.be.rejectedWith('opts.secret required');
  });

  var requiredFields = ['log', 'secret', 'lookupAccount', 'updateTokens', 'updateAccount'];
  for (var field of requiredFields) {
    testMissingField(field);
  }

  it('test Login ADT cannot verify', () => {
    var a = new Auth(allOpts);
    var login = new AuthLib.Logins.abstract('login', a);
    return login.verify()
      .should.eventually.be.rejectedWith('Subclass must override verify() method');
  });
});

function testMissingField(field) {
  it('invalid construction missing ' + field, () => {
    var opts = lodash.clone(allOpts);
    delete opts[field];

    return new Promise((resolve) => {
      resolve(new Auth(opts));
    })
    .should.eventually.be.rejectedWith('opts.' + field + ' required');
  });
}
