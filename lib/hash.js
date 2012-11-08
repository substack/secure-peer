var crypto = require('crypto');

module.exports = function hash (key, payload) {
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(payload);
    return signer.sign(key, 'base64');
};
