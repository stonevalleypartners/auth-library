'use strict';

var bcrypt = require('bcryptjs');
var Login = require('./login.js');

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
    this.authLib.log.error({body: req.body}, 'local::verify called');
    var field = {};
    if(req.body.id) field.id = req.body.id;
    else if(req.body.email) field.email = req.body.email;
    else return res.status(400).json({message: 'id or email field required'});

    return this.authLib.opts.lookupAccount(field)
      .then((user) => {
        if(!user) throw new Error('user not found');

        if(!bcrypt.compareSync(req.body.password, user.password)) {
          throw new Error('hash compare failed');
        }
        return this.sendSuccess(req.body.access_type, res, user);
      })
      .catch((err) => {
        this.authLib.log.info({err: err, req: req}, 'local verify error');
        return this.sendFail(res);
      });
  }
}

module.exports = Local;
