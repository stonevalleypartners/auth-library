'use strict';

var Login = require('./login.js');
var User = require('../user.js');

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
}

module.exports = Local;
