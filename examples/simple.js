'use strict';

var express = require('express');
var bodyParser = require('body-parser');
var lodash = require('lodash');

//import AuthLib from './lib';
var AuthLib = require('../lib');

function lookupAccount() {
  return Promise.resolve({
    id: '11111',
    password: '$2a$10$qZ0pb8FTfxBcRw.sWTsA6en1yH9y8Vf2N9n9eMrA210yqac6XVUKW',
  });
}

var app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

var opts = {
  secret: 'testAuthLib',
  lookupAccount: lookupAccount,
  updateTokens: lodash.noop,
  updateAccount: lodash.noop,
};
var auth = new AuthLib.Auth(opts);
new AuthLib.Logins.local('local', auth);

app.get('/', auth.addAuthMiddleware(), function(req, res) {
  console.log('user', req.user);
  console.log('userid', req.userid);
  res.json({status: 'all clear'});
});

auth.initExpress(app);

var server = app.listen(3000, function() {
  var host = server.address().address;
  var port = server.address().port;

  console.log('Example app listening at http://%s:%s', host, port);
});
