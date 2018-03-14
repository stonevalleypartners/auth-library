'use strict';

var express = require('express');
var bodyParser = require('body-parser');
var lodash = require('lodash');
var bunyan = require('bunyan');

var log = bunyan.createLogger({name: 'simple'});

//import AuthLib from './lib';
var AuthLib = require('../lib');

function lookupAccount() {
  var u = new AuthLib.User();
  u.id = '11111';
  u.setPassword('simple');
  return Promise.resolve(u);
}

var app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

var opts = {
  secret: 'testAuthLib',
  lookupAccount: lookupAccount,
  updateTokens: lodash.noop,
  log,
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
