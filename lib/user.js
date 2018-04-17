'use strict';

var bcrypt = require('bcryptjs');

/**
 * abstract base class for users
 */

class User {
  /**
   * preps authLib required data structures
   **/
  constructor() {
    this.auth = {};
    this.social = {};
  }

  /**
   * stores a hash of the users password for comparing later
   * @param {String} pw - user's password
   * @returns {Promise}
   **/
  setPassword(pw) {
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(pw, salt);
    this.auth.hashedPassword = hash;
    return Promise.resolve();
  }

  /**
   * compares a password with the stored hashedPassword
   * @param {String} pw - password to check for equality
   * @returns {Promise} rejected if hash fails; otherwise resolved with true
   **/
  comparePassword(pw) {
    if(!bcrypt.compareSync(pw, this.auth.hashedPassword)) {
      return Promise.reject(new Error('hash compare failed'));
    }
    return Promise.resolve(true);
  }

  /**
   * checks whether a user has previously stored a particular refresh token
   * @param {String} token - refresh token to confirm that we have created previously
   * @returns {Promise} subclasses are responsible for overriding this, resolve true to allow access
   **/
  checkRefreshToken() {
    return Promise.reject(new Error('subclass must override'));
  }

  /**
   * saves the user object; subclasses must override this method
   **/
  save() {
    return Promise.reject(new Error('subclass must override save() method'));
  }

  /**
   * override default JSON.stringification so it doesn't include auth values
   * @returns {Object}
   **/
  toJSON() {
    var copy = Object.assign({}, this);
    delete copy.auth;
    return copy;
  }
}

module.exports = User;
