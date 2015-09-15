var bunyan = require('bunyan');

function getLogger(name) {
  var logOpts = {
    name: name,
    streams: [{path: 'mocha.log', level: 'debug'}],
    serializers: bunyan.stdSerializers
  };
  return bunyan.createLogger(logOpts);
}

module.exports = getLogger;
