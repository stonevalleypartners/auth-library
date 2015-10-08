var AuthLib = require('../lib');
var express = require('express');
var bodyParser = require('body-parser');
var http = require('http');
var request = require('request-promise');
var lolex = require('lolex');

var chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
var getLogger = require('./lib/getLogger');
var portFinder = require('svp-portfinder');
var UserStore = require('./lib/simpleUserStore');

describe('bearer', () => {
  var app = express();
  var server = http.createServer(app);
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());

  var auth, url, log, users;

  before(() => {
    log = getLogger('bearer');

    users = new UserStore();
    var opts = users.createAuthLibOpts();
    opts.log = log;
    opts.secret = 'bearer tests';
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
    var setupUser = users.addUser(auth, {id: 123, password: 'secret2', email: 'foo@svp.com'});
    return Promise.all([setupServer, setupUser]);
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
        body.should.have.deep.property('user.id', 123);
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
});
