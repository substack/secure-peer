var crypto = require('crypto');

module.exports = function pad (msg) {
    var n = Math.ceil(msg.length / 256) * 256;
    var b = Buffer(crypto.randomBytes(n));
    
    if (Buffer.isBuffer(msg)) {
        msg.copy(b, 0);
    }
    else {
        b.write(msg, 0);
    }
    return b;
};
