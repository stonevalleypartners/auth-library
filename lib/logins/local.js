'use strict';

var Login = require('./login.js');
var User = require('../user.js');
var jwt = require('jsonwebtoken');

/**
  a local login; used for email/password login
*/
class Local extends Login {
  /**
    construct a new instance
    @param loginName - name of the login to use in constructing the route
    @param authLib - authentication library
  */
  constructor(loginName, authLib) {
    super(loginName, authLib);
  }

  /**
    verify a login attempt
    @param req - http request object
    @param res - http response object
  */
  verify(req, res) {
    this.authLib.log.info({body: req.body}, 'local::verify called');
    var field = {};
    if(req.body.id) field.id = req.body.id;
    else if(req.body.email) field.email = req.body.email;
    else return res.status(400).json({message: 'id or email field required'});

    var user;
    return this.authLib.opts.lookupAccount(field)
      .then((u) => {
        if(!u) throw new Error('user not found');
        if(!(u instanceof User)) throw new Error('lookupAccount() retval must be a subclass of User');
        user = u;
        return user.comparePassword(req.body.password);
      })
      .then(() => this.sendSuccess(req.body.access_type, res, user))
      .catch((err) => {
        this.authLib.log.error({err: err.message, req: req}, 'local verify error');
        return this.sendFail(res);
      });
  }

  /**
    verify a refresh token
    @param req - http request object
    @param res - http response object
  */
  verifyRefresh(req, res) {
    this.authLib.log.info({body: req.body}, 'local::verifyRefresh called');

    var refresh = req.body.refresh_token;
    var token;
    try {
      token = jwt.verify(refresh, this.authLib.opts.secret, {algorithms: ['HS256']});
    } catch(err) {
      return this.sendFail(res);
    }

    var user;
    return this.authLib.opts.lookupAccount({id: token.id})
      .then((u) => {
        if(!u) throw new Error('user not found');
        if(!(u instanceof User)) throw new Error('lookupAccount() retval must be a subclass of User');
        user = u;
        return user.checkRefreshToken(refresh);
      })
      .then((refreshTokenOk) => {
        if(!refreshTokenOk) {
          throw new Error('refresh token not found')
        }
      })
      .then(() => this.sendSuccess(req.body.access_type, res, user))
      .catch((err) => {
        this.authLib.log.error({err: err.message, req: req}, 'local verifyRefresh error');
        return this.sendFail(res);
      });
  }
}

module.exports = Local;
