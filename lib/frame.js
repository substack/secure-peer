var hash = require('./hash');
var verify = require('./verify');

module.exports = Frame;

function Frame () {
    if (!(this instanceof Frame)) return new Frame;
    this.seq = { pack : 0, unpack : 0 };
}

Frame.prototype.pack = function (key, token, msg) {
    var seq = (this.seq.pack ++) + ',';
    
    if (msg === undefined) {
        // end message
        return JSON.stringify([ hash(key, seq + token) ]) + '\n';
    }
    
    var s = msg.toString('base64');
    return JSON.stringify([ s, hash(key, seq + token + s) ]) + '\n';
};

Frame.prototype.unpack = function (key, token, buf) {
    try {
        var x = JSON.parse(buf);
    } catch (e) { return undefined }
    if (!Array.isArray(x)) return undefined;
    if (x.length !== 2 && x.length !== 1) return undefined;
    
    var seq = (this.seq.unpack ++) + ',';
    var v;
    if (x.length === 1) {
        v = verify(key, seq + token, x[0]);
        if (v) return 'end'
        else return undefined
    }
    
    v = verify(key, seq + token + x[0], x[1]);
    if (!v) return undefined;
    
    return x;
};
