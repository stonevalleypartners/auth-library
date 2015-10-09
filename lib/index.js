module.exports.Auth = require('./authLib.js');
module.exports.Logins = {
  abstract: require('./logins/login.js'),
  google: require('./logins/google.js'),
  local: require('./logins/local.js'),
};
