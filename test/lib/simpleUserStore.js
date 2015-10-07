'use strict';

var lodash = require('lodash');

class UserStore {
  constructor() {
    this.users = [];
  }

  addUser(auth, obj) {
    // remove the user if it's already in the array
    this.removeUser(obj.id);

    // hash password
    return auth.getHashedPassword(obj.password)
      .then((hash) => {
        // add user
        obj.password = hash;
        this.users.push(obj);
      });
  }

  removeUser(id) {
    lodash.remove(this.users, {id: id});
  }

  lookupAccount(field) {
    return Promise.resolve(lodash.find(this.users, field));
  }

  updateAccount(user, update) {
    this.lookupAccount({id: user.id})
      .then((u) => {
        lodash.extend(u, update);
      });
  }

  createAuthLibOpts() {
    return {
      lookupAccount: this.lookupAccount.bind(this),
      updateTokens: lodash.noop,
      updateAccount: this.updateAccount.bind(this),
    };
  }
}

module.exports = UserStore;
