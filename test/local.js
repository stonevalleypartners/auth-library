var AuthLib = require('../lib');
var express = require('express');
var bodyParser = require('body-parser');
var http = require('http');
var request = require('request-promise');

var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');
var portFinder = require('svp-portfinder');
var UserStore = require('./lib/simpleUserStore');

describe('Local', () => {
  var app = express();
  var server = http.createServer(app);
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());

  var auth, url;
  var log = getLogger('local');
  
  var users = new UserStore();

  it('create authLib', () => {
    var opts = users.createAuthLibOpts();
    opts.log = log;
    opts.secret = 'testAuthLib';
    opts.maxRefreshTokens = 0;
    auth = new AuthLib.Auth(opts);
    new AuthLib.Logins.local('local', auth);
    auth.initExpress(app);
    return portFinder()
      .then((port) => {
        url = 'http://localhost:' + port;
        return new Promise((resolve, reject) => {
          server.listen(port);
          server.on('listening', resolve);
          server.on('error', reject);
        });
      });
  });

  it('initialize users', () => {
    return users.addUser({id: 123, password: 'secret', email: 'foo@svp'})
      .then(() => {
        return users.addUser({id: 'abc', password: 'sekret', email: 'bar@svp'});
      });
  });

  it('login valid user by id number', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 123, password: 'secret'}
    };
    log.error({data: reqOpts}, 'request opts');
    return request(reqOpts)
      .then((data) => {
        log.info({token: data}, 'local login user by id number');
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 123);
      });
  });

  it('login valid user by id string', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 'abc', password: 'sekret'}
    };
    log.error({data: reqOpts}, 'request opts');
    return request(reqOpts)
      .then((data) => {
        log.info({token: data}, 'local login user by id string');
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 'abc');
      });
  });

  it('login user does not exist', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 'foo', password: 'sekret'}
    };
    log.error({data: reqOpts}, 'request opts');
    return request(reqOpts)
      .catch((data) => {
        log.info({body: data.response.body}, 'login user does not exist');
        data.should.have.property('statusCode', 401);
        data.should.have.deep.property('response.body.message', 'Unauthorized');
        return Promise.reject(data);
      })
      .should.eventually.be.rejected;
  });

  it('login user with bad password', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 'abc', password: 'wrongpass'}
    };
    log.error({data: reqOpts}, 'request opts');
    return request(reqOpts)
      .catch((data) => {
        log.info({body: data.response.body}, 'login user with bad password');
        data.should.have.property('statusCode', 401);
        data.should.have.deep.property('response.body.message', 'Unauthorized');
        return Promise.reject(data);
      })
      .should.eventually.be.rejected;
  });

  it('login valid user by email', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {email: 'bar@svp', password: 'sekret'}
    };
    log.error({data: reqOpts}, 'request opts');
    return request(reqOpts)
      .then((data) => {
        log.info({token: data}, 'local login user by id string');
        data.should.have.property('access_token');
        data.should.have.property('token_type', 'bearer');
        data.should.have.property('expires_in', 3600);
        data.should.have.property('id', 'abc');
      });
  });

  it('login user with missing credentials', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {password: 'wrongpass'},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((data) => {
        log.debug({body: data}, 'login user with missing credentials');
        data.should.have.property('statusCode', 400);
        data.should.have.deep.property('body.message', 'id or email field required');
      });
  });

  after(() => {
    server.close();
  });
});


