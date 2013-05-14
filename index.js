var crypto = require('crypto');
var through = require('through');
var es = require('event-stream');

var createAck = require('./lib/ack');
var framer = require('./lib/frame');
var hash =require('./lib/hash');
var verify = require('./lib/verify');
var pickCipher = require('./lib/pick_cipher');
var toBuffer = require('./lib/to_buffer');

var defaultCiphers = ['RC4'];

module.exports = function (keys, opts) {
    if (!opts) opts = {};
    var ciphers = opts.ciphers || defaultCiphers;

    var group = 'modp5';
    var dh = crypto.getDiffieHellman(group);
    dh.generateKeys();
    dh.group = group;
    
    return function (cb) {
        var sec = securePeer(dh, keys, ciphers);
        if (typeof cb === 'function') sec.on('connection', cb);
        return sec;
    };
};

function securePeer (dh, keys, ciphers) {
    var stream, secret, token;
    var frame = framer();
    var cipher;
    
    function unframer (buf) {
        var uf = frame.unpack(stream.id.key.public, token, buf);
        if (uf === 'end') {
            if (stream && !destroyed) stream.emit('end');
            if (!destroyed) sec.emit('end');
            
            if (stream && !stream.closed) stream.emit('close');
            
            if (!sec.closed) sec.emit('close');
            return;
        }
        if (!uf) {
            stream.destroy();
            sec.destroy();
            return;
        }
        var msg = Buffer(uf[0], 'base64');
        
        var decrypt = crypto.createDecipher(cipher, secret);
        var body = toBuffer(decrypt.update(msg));
        var fin = toBuffer(decrypt.final());
        stream.emit('data', Buffer.concat([body, fin]));
    }
    
    var lines = [];
    
    var end = (function () {
        var sentEnd = false;
        return function end () {
            if (destroyed) return;
            if (sentEnd) return;
            sentEnd = true;
            sec.emit('data', frame.pack(keys.private, token)); // end
        }
    })();
    
    var lineNum = 0;
    var sec = es.connect(es.split(), through(function (line) {
        lineNum ++;
        
        if (lineNum > 1 && lines) return lines.push(line);
        else if (lineNum > 1) return unframer(line);
        
        try {
            var header = JSON.parse(line);
        } catch (e) { return sec.destroy() }
        
        sec.emit('header', header);
    }, end));
    
    var destroyed = false;
    sec.destroy = function () {
        if (!destroyed && !sec.closed) {
            sec.emit('close');
        }
        if (!destroyed && stream && !stream.closed) {
            stream.emit('close');
        }
        destroyed = true;
    };
    
    sec.on('close', function () { sec.closed = true });
    
    sec.on('accept', function (ack) {
        var pub = ack.payload.dh.public;
        secret = dh.computeSecret(pub, 'base64', 'base64');
        
        stream = through(write, end);
        stream.id = ack;
        stream.on('close', function () { stream.closed = true });
        
        function write (buf) {
            var encrypt = crypto.createCipher(cipher, secret);
            var body = toBuffer(encrypt.update(buf));
            var fin = toBuffer(encrypt.final());
            var s = Buffer.concat([body, fin]);
            sec.emit('data', frame.pack(keys.private, token, s));
        }
        
        sec.emit('connection', stream);
        
        var lines_ = lines;
        lines = undefined;
        lines_.forEach(unframer);
    });
    
    sec.once('header', function (meta) {
        var payload = JSON.parse(meta.payload);
        token = outgoing.token > payload.token
            ? outgoing.token + payload.token
            : payload.token + outgoing.token
        ;
        
        var ack = createAck(sec.listeners('identify').length);
        ack.key = payload.key;
        ack.outgoing = outgoing;
        ack.payload = payload;
        ack.ciphers = payload.ciphers;
        
        ack.on('accept', function () {
            sec.emit('accept', ack);
        });
        
        ack.on('reject', function () {
            if (!sec.closed) sec.emit('close');
        });
        
        cipher = ack.cipher = outgoing.token > payload.token
            ? pickCipher(ciphers, payload.ciphers)
            : pickCipher(payload.ciphers, ciphers)
        ;
        if (!cipher) {
            sec.emit('clientError', new Error('no common ciphers'))
            return ack.reject();
        }
        
        var v = verify(payload.key.public, meta.payload, meta.hash);
        if (!v) return ack.reject();
        
        process.nextTick(function () {
            sec.emit('identify', ack);
        });
    });
    
    sec.on('pipe', function () {
        process.nextTick(sendOutgoing);
    });
    
    var outgoing = {
        token : crypto.randomBytes(64).toString('base64'),
        key : {
            type : 'rsa',
            public : keys.public,
        },
        dh : {
            group : dh.group,
            public : dh.getPublicKey('base64')
        },
        ciphers : ciphers
    };
    
    function sendOutgoing () {
        var outs = JSON.stringify(outgoing);
        
        sec.emit('data', JSON.stringify({
            hash : hash(keys.private, outs),
            payload : outs
        }) + '\n');
    }
    
    return sec;
};
