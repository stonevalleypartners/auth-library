'use strict';

var lodash = require('lodash');
var User = require('../../lib/user.js');

class SimpleUser extends User {
  constructor(obj) {
    super();
    Object.assign(this, obj);
  }

  save() {
    return Promise.resolve();
  }
}

class UserStore {
  constructor() {
    this.users = [];
  }

  addUser(obj) {
    // remove the user if it's already in the array
    this.removeUser(obj.id);

    var pw;
    if(obj.password) {
      // remove password from obj (keep a temp copy)
      pw = obj.password;
      delete obj.password;
    }

    var u = new SimpleUser(obj);
    this.users.push(u);

    // if user contains a password; replace with the hashed version
    if(pw) {
      return u.setPassword(pw);
    } else {
      return Promise.resolve();
    }
  }

  removeUser(id) {
    lodash.remove(this.users, {id: id});
  }

  lookupAccount(field) {
    return Promise.resolve(lodash.find(this.users, field));
  }

  registerExternalAccount(accountInfo) {
    var key = Object.keys(accountInfo)[0];
    var obj = {
      name: accountInfo[key].name,
      id: key + ':' + accountInfo[key].id
    };
    var u = new SimpleUser(obj);
    this.users.push(u);
    return Promise.resolve(u);
  }

  createAuthLibOpts() {
    return {
      lookupAccount: this.lookupAccount.bind(this),
      registerExternalAccount: this.registerExternalAccount.bind(this),
      updateTokens: lodash.noop,
    };
  }
}

module.exports = UserStore;
