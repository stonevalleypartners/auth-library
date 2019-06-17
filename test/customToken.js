const AuthLib = require('../lib');
const express = require('express');
const bodyParser = require('body-parser');
const http = require('http');
const request = require('request-promise');

const chai = require('chai');
chai.use(require('chai-as-promised'));
chai.should();
const getLogger = require('./lib/getLogger');
const portFinder = require('svp-portfinder');
const UserStore = require('./lib/simpleUserStore');

function getExtendedJWTFields(user) {
  return {email: user.email}
}

describe('custom token', () => {
  const app = express();
  const server = http.createServer(app);
  app.use(bodyParser.urlencoded({extended: true}));
  app.use(bodyParser.json());

  var auth, url, log, users;

  before(() => {
    log = getLogger('bearer');

    users = new UserStore();
    var opts = users.createAuthLibOpts();
    opts.log = log;
    opts.secret = 'bearer tests';
    opts.getExtendedJWTFields = getExtendedJWTFields;
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
        body.should.have.nested.property('user.email', 'foo@svp.com');
      });
  });
});
