var lodash = require('lodash');
var AuthLib = require('../lib');
var Auth = AuthLib.Auth;

const generateRSAKeys = require('./lib/generateRSA');
var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');

var log = getLogger('constructor');
var allOpts = {
  log: log,
  signAlg: 'HS256',
  secret: 'auth constructor tests',
  tokenDuration: 1800,
  maxRefreshTokens: 2,
  lookupAccount: lodash.noop,
  registerExternalAccount: lodash.noop,
  updateTokens: lodash.noop,
};

describe('auth constructor options', () => {
  before(async () => {
    allOpts.keys = await generateRSAKeys();
  });

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

  it('valid construction using signAlg default', () => {
    const opts = lodash.clone(allOpts);
    delete opts.signAlg;

    var a = new Auth(opts);
    a.opts.signAlg.should.equal('HS256');
  });

  it('valid construction using RS256 signAlg', async () => {
    const opts = lodash.clone(allOpts);
    opts.signAlg = 'RS256';
    opts.keys = await generateRSAKeys();

    var a = new Auth(opts);
    a.opts.signAlg.should.equal('RS256');
  });

  var requiredFields = ['log', 'lookupAccount', 'updateTokens', 'keys'];
  const overrides = { signAlg: 'RS256' };

  for (var field of requiredFields) {
    testMissingField(overrides, field);
  }
  testMissingField({}, 'secret');

  it('test Login ADT cannot verify', () => {
    var a = new Auth(allOpts);
    var login = new AuthLib.Logins.abstract('login', a);
    return login.verify()
      .should.eventually.be.rejectedWith('Subclass must override verify() method');
  });
});

function testMissingField(overrides, field) {
  it('invalid construction missing ' + field, () => {
    var opts = { ...allOpts, ...overrides };
    delete opts[field];

    return new Promise((resolve) => {
      resolve(new Auth(opts));
    })
    .should.eventually.be.rejectedWith('opts.' + field + ' required');
  });
}
