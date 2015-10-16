'use strict';

/**
 * abstract base class for logging in
 */
class Login {
  /**
    constructor
    @param loginName - name of the login will be used to construct route
    @param authLib - authentication library to which this login method will be added
  */
  constructor(loginName, authLib) {
    this.loginName = loginName;
    this.authLib = authLib;

    this.authLib.logins.push(this);
  }

  /**
    configures express routes for handling login
    @param app - express app
  */
  configureRoute(app) {
    var v = this.verify.bind(this);
    this.authLib.log.error('adding route to app');
    app.post('/auth/' + this.loginName + '/verify', v);
  }

  /**
    verifies a login attempt
  */
  verify() {
    return Promise.reject(new Error('Subclass must override verify() method'));
  }

  /**
    send response to login the user (verify succeeded)
    @param accessType - offline 
    @param res - http response
    @param user - user record for login
  */
  sendSuccess(accessType, res, user) {
    return this.authLib.getAccessToken(user, accessType)
      .then(token => res.json(token));
  }

  /**
    send fail response to login the user
    @param res - http response
  */
  sendFail(res) {
    return Promise.resolve(res.status(401).json({message: 'Unauthorized'}));
  }
}

module.exports = Login;
