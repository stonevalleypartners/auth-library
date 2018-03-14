'use strict';

var Login = require('./login.js');
var User = require('../user.js');
var request = require('request-promise');
var lodash = require('lodash');

/**
  google social login; app obtains google OAuth token; securely sends to server
*/
class Google extends Login {
  /**
    construct a new instance
    @param loginName - name of the login to use in constructing the route
    @param authLib - authentication library
    @param {object} opts - options
    @param {array} opts.clientIDs - array of google clientIDs; ensures token
                                    was created for this app
    @param {string} opts.authHost - google authentication host; override for stub testing
  */
  constructor(loginName, authLib, opts) {
    super(loginName, authLib);
    opts = opts || {};
    this.clientIDs = opts.clientIDs || [];
    this.authHost = opts.authHost || 'http://www.googleapis.com';
  }

  /**
    verify a login attempt
    @param req - http request object
    @param res - http response object
  */
  verify(req, res) {
    var token = req.body.accessToken;
    var tokenInfoUri = this.authHost + '/oauth2/v1/tokenInfo?access_token=' + token;
    var userInfoUri = this.authHost + '/oauth2/v1/userinfo?access_token=' + token;
    var userInfo;
    Promise.all([request(tokenInfoUri), request(userInfoUri)])
      .then((data) => {
        var tokenInfo = JSON.parse(data[0]);
        if(tokenInfo.error) throw new Error('tokenInfo error: ' + tokenInfo.error);
        if(!lodash.isEmpty(this.clientIDs)) {
          if(!lodash.contains(this.clientIDs, tokenInfo.issued_to)) {
            throw new Error('tokenInfo error: bad issued to');
          }
        }

        userInfo = JSON.parse(data[1]);
        // lookup internal user based on userInfo.id
        return this.authLib.opts.lookupAccount({google: userInfo.id});
      })
      .then((user) => {
        if(!user) {
          return createNewUser(this.authLib, userInfo)
            .then((newUser) => this.sendSuccess(req.body.access_type, res, newUser));
        }
        if(!(user instanceof User)) {
          throw new Error('lookupAccount() retval must be subclass of user');
        }

        this.authLib.log.info({user: user, userInfo: userInfo}, 'handle user');
        var doSave = false;
        for(var prop of ['name', 'email', 'picture']) {
          if(user.social[prop] !== userInfo[prop]) {
            doSave = true;
            user.social[prop] = userInfo[prop];
          }
        }
        if(doSave) user.save();

        return this.sendSuccess(req.body.access_type, res, user);
      })
      .catch((err) => {
        this.authLib.log.info({err: err}, 'auth google verify failed');
        return this.sendFail(res);
      });
  } 
}

function createNewUser(authLib, userInfo) {
  if(!authLib.opts.registerExternalAccount) {
    throw new Error('creating users from social login requires registerExternalAccount');
  }

  return authLib.opts.registerExternalAccount({google: userInfo})
    .then((user) => {
      user.social.googleID = userInfo.id;
      for(var prop of ['name', 'email', 'picture']) {
        user.social[prop] = userInfo[prop];
      }
      user.save();
      authLib.log.info({user: user}, 'what does user look like now?');
      return Promise.resolve(user);
    });
}

module.exports = Google;
