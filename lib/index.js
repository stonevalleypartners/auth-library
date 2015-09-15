module.exports.Auth = require('./authLib.js');
module.exports.Logins = {
  abstract: require('./logins/login.js'),
  local: require('./logins/local.js'),
};
