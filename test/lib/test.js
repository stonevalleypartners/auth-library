'use strict';

var getLogger = require('./getLogger');
var express = require('express');
var bodyParser = require('body-parser');
var http = require('http');
var portFinder = require('svp-portfinder');
var RestStub = require('svp-reststub');
var lodash = require('lodash');

class Test {
  constructor(name) {
    this.name = name;
    this.chai = require('chai');
    this.chai.use(require('chai-as-promised'));
    this.should = this.chai.should();

    this.log = getLogger(name);

    this.users = new (require('./simpleUserStore'))();
  }

  createExpressServer() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.app.use(bodyParser.urlencoded({extended: true}));
    this.app.use(bodyParser.json());

    return portFinder()
      .then((port) => {
        this.appUrl = 'http://localhost:' + port;
        return new Promise((resolve, reject) => {
          this.server.on('listening', resolve);
          this.server.on('error', reject);
          this.server.listen(port);
        });
      });
  }

  closeExpressServer() {
    this.server.close();
    this.server = undefined;
  }

  createGoogleAuthStub() {
    this.google = {};
    this.google.stub = new RestStub(this.log);
    return this.google.stub.start()
      .then((url) => this.google.url = url);
  }

  setGoogleAuthStubs(userId, issuedTo, userOverrides) {
    var tokenInfo = {
      audience: issuedTo,
      issued_to: issuedTo,
      user_id: userId,
      scope: 'profile',
      expires_in: 3600
    };
    this.google.stub.setResponse('tokenInfo', '/oauth2/v1/tokenInfo', tokenInfo);
    var userInfo = {
      id: userId,
      name: 'Jane Doe',
      picture: 'http://example.com/image/' + userId + '.jpg',
      email: 'doe@example.com',
    };
    userInfo = lodash.extend(userInfo, userOverrides);
    this.google.stub.setResponse('userInfo', '/oauth2/v1/userinfo', userInfo);
  }

  closeServices() {
    if(this.server) {
      this.server.close();
      this.server = undefined;
    }
    if(this.google) {
      this.google.stub.stop();
    }
  }
}

module.exports = Test;
