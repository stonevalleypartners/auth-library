const { generateKeyPair } = require('crypto');

function generateRSAKeys() {
  const opts = {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  };
  return new Promise((resolve, reject) => {
    generateKeyPair('rsa', opts, (err, pubKey, privKey) => {
      if(err) {
        return reject(err);
      }
      resolve({ public: pubKey, private: privKey });
    });
  });
}

module.exports = generateRSAKeys;
