var hash = require('./hash');
var verify = require('./verify');

exports.pack = function (key, token, msg) {
    var s = msg.toString('base64');
    return JSON.stringify([ s, hash(key, token + s) ]) + '\n';
};

exports.unpack = function (key, token, buf) {
    try {
        var x = JSON.parse(buf);
    } catch (e) { return undefined }
    if (!Array.isArray(x)) return undefined;
    if (x.length === 0) return 'end';
    if (x.length !== 2) return undefined;
    
    var v = verify(key, token + x[0], x[1]);
    if (!v) return undefined;
    
    return x;
};
