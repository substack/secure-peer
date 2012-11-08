var crypto = require('crypto');

module.exports = function verify (key, msg, hash) {
    return crypto.createVerify('RSA-SHA256')
        .update(msg)
        .verify(key, hash, 'base64')
    ;
};
