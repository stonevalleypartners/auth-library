'use strict';

var Test = require('./lib/test.js');
var User = require('../lib').User;

describe('user', () => {
  new Test('user');

  it('save must be overridden', () => {
    var u = new User();
    u.save()
      .should.eventually.be.rejectedWith('subclass must override save() method');
  });

  class SubUser extends User {
    constructor(obj) {
      super();
      Object.assign(this, obj);
    }

    save() {
      return Promise.resolve(JSON.stringify(this));
    }
  }

  it('constructed user has all fields', () => {
    var u = new SubUser({foo: 'abc', bar: 123});
    u.should.have.property('foo', 'abc');
    u.should.have.property('bar', 123);
    u.should.have.property('auth');
    u.auth.should.deep.equal({refreshTokens: []});
    u.should.have.property('social');
    u.social.should.be.empty;
  });

  it('stringified user should not have auth object', () => {
    var u = new SubUser({foo: 'abc', bar: 123});
    var obj = JSON.parse(JSON.stringify(u));
    obj.should.have.property('foo', 'abc');
    obj.should.have.property('bar', 123);
    obj.should.not.have.property('auth');
    obj.should.have.property('social');
    obj.social.should.be.empty;
  });
});
