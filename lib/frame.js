var hash = require('./hash');
var verify = require('./verify');

exports.pack = function (key, msg, size) {
    var s = msg.toString('base64');
    var payload = JSON.stringify([ s, size ]);
    return JSON.stringify([ s, size, hash(key, payload) ]) + '\n';
};

exports.unpack = function (key, buf) {
    try {
        var x = JSON.parse(buf);
    } catch (e) { return undefined }
    if (!Array.isArray(x)) return undefined;
    if (x.length === 0) return 'end';
    if (x.length !== 3) return undefined;
    
    var payload = JSON.stringify(x.slice(0,2));
    var v = verify(key, payload, x[2]);
    if (!v) return undefined;
    
    return x;
};
