var AuthLib = require('../lib');
var express = require('express');
var bodyParser = require('body-parser');
var http = require('http');
var request = require('request-promise');
var lolex = require('lolex');

const generateRSAKeys = require('./lib/generateRSA');
var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');
var portFinder = require('svp-portfinder');
var UserStore = require('./lib/simpleUserStore');

describe('rs256', () => {
  var app = express();
  var server = http.createServer(app);
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());

  var auth, url, log, users;
  let refreshToken;

  before(async () => {
    log = getLogger('rs256');

    users = new UserStore();
    var opts = users.createAuthLibOpts();
    opts.log = log;
    opts.signAlg = 'RS256';
    opts.keys = await generateRSAKeys();
    auth = new AuthLib.Auth(opts);
    new AuthLib.Logins.local('local', auth);
    auth.initExpress(app);

    app.get('/private', auth.addAuthMiddleware(), (req, res) => {
      res.json({user: req.user});
    });

    var setupServer = portFinder()
      .then((port) => {
        url = 'http://localhost:' + port;
        return new Promise((resolve, reject) => {
          server.listen(port);
          server.on('listening', resolve);
          server.on('error', reject);
        });
      });
    var setupUser = users.addUser({id: 123, password: 'secret2', email: 'foo@svp.com'});
    return Promise.all([setupServer, setupUser]);
  });

  after(() => {
    server.close();
  });

  var bearer;
  it('login', () => {
    var reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 123, password: 'secret2'}
    };
    return request(reqOpts)
      .then((data) => {
        bearer = data.access_token;
      });
  });

  it('access auth-protected api', () => {
    var reqOpts = {
      uri: url + '/private',
      auth: {'bearer': bearer},
    };
    return request(reqOpts)
      .then((data) => {
        log.error({data: data}, 'private api response');
        var body = JSON.parse(data);
        body.should.have.nested.property('user.id', 123);
      });
  });

  it('bad token is denied', () => {
    var reqOpts = {
      uri: url + '/private',
      auth: {'bearer': bearer + 'foo'},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((data) => {
        log.error({data: data}, 'private api response - bad token');
        data.should.have.property('statusCode', 401);
        data.should.have.property('body', 'Unauthorized');
      });
  });

  it('expired token is denied', () => {
    // fast forward one hour + 1ms, using lolex
    var clock = lolex.install(Date.now() + 3600*1000 + 1);
    var reqOpts = {
      uri: url + '/private',
      auth: {'bearer': bearer},
      simple: false,
      resolveWithFullResponse: true,
    };
    return request(reqOpts)
      .then((data) => {
        log.error({data: data}, 'private api response - bad token');
        data.should.have.property('statusCode', 401);
        data.should.have.property('body', 'Unauthorized');
        clock.uninstall();
      });
  });

  it('login user, request refresh token', async () => {
    const reqOpts = {
      uri: url + '/auth/local/verify',
      method: 'post',
      json: {id: 123, password: 'secret2', access_type: 'offline'},
    };
    const data = await request(reqOpts);
    data.should.have.property('access_token');
    data.should.have.property('refresh_token');
    refreshToken = data.refresh_token;
  });

  it('can obtain access_token via refresh_token', async () => {
    const reqOpts = {
      uri: url + '/auth/local/token',
      method: 'post',
      json: {refresh_token: refreshToken},
    };
    const data = await request(reqOpts);
    data.should.have.property('access_token');
    data.should.have.property('token_type', 'bearer');
    data.should.have.property('expires_in', 3600);
    data.should.have.property('id', 123);
    data.should.not.have.property('refresh_token');
  });
});
