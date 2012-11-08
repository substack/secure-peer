var crypto = require('crypto');
var header = require('./lib/header');
var through = require('through');
var createAck = require('./lib/ack');

module.exports = function (keys) {
    var group = 'modp5';
    var dh = crypto.getDiffieHellman(group);
    dh.generateKeys();
    
    return function (cb) {
        var buffers = [];
        var stream, encrypt, decrypt;
        
        var sec = header(function (buf) {
            if (decrypt) {
                var uf = unframe(stream.id.key, buf);
                if (!uf) {
                    stream.destroy();
                    this.destroy();
                    return;
                }
                var s = decrypt.update(String(uf));
                stream.emit('data', Buffer(s));
            }
            else buffers.push(buf)
        });
        
        sec.on('accept', function (ack) {
            var pub = ack.payload.dh.public;
            var k = dh.computeSecret(pub, 'base64', 'base64');
            
            encrypt = crypto.createCipher('aes-256-cbc', k);
            
            stream = through(write, end);
            stream.id = ack;
            
            function write (buf) {
                var s = encrypt.update(String(pad(buf)));
                sec.emit('data', frame(keys.private, Buffer(s)));
            }
            
            function end () {
                sec.emit('data', ecrypt.final());
                sec.emit('end');
                sec.emit('close');
            }
            
            sec.emit('connection', stream);
            
            decrypt = crypto.createDecipher('aes-256-cbc', k);
            
            buffers.forEach(function (buf) {
                var uf = unframe(stream.id.key, buf);
                if (!uf) {
                    stream.destroy();
                    sec.destroy();
                    return;
                }
                stream.emit('data', decrypt.update(uf));
            });
            buffers = undefined;
        });
        
        sec.once('header', function (meta) {
            var payload = JSON.parse(meta.payload);
            
            var v = verify(payload.key.public, meta.payload, meta.hash);
            if (!v) return sec.reject();
            
            var ack = createAck(sec.listeners('identify').length);
            ack.key = payload.key;
            ack.outgoing = outgoing;
            ack.payload = payload;
            
            ack.on('accept', function () {
                sec.emit('accept', ack);
            });
            
            ack.on('reject', function () {
                sec.emit('close');
            });
            
            sec.emit('identify', ack);
        });
        
        sec.on('pipe', function () {
            process.nextTick(sendOutgoing);
        });
        
        var outgoing;
        function sendOutgoing () {
            outgoing = JSON.stringify({
                key : {
                    type : 'rsa',
                    public : keys.public,
                },
                dh : {
                    group : group,
                    public : dh.getPublicKey('base64')
                }
            });
            sec.emit('data', JSON.stringify({
                hash : hash(keys.private, outgoing),
                payload : outgoing
            }) + '\n');
        }
        
        if (typeof cb === 'function') sec.on('connection', cb);
        return sec;
    };
};

function zeros (n) {
    var b = Buffer(n);
    for (var i = 0; i < n; i++) b[i] = 0;
    return b;
}

function pad (msg) {
    var n = Math.ceil(msg.length / 256) * 256;
    var b = zeros(n);
    
    if (Buffer.isBuffer(msg)) {
        msg.copy(b, 0);
    }
    else {
        b.write(msg, 0);
    }
    return b;
}

function hash (key, payload) {
    var signer = crypto.createSign('RSA-SHA256');
    signer.update(payload);
    return signer.sign(key, 'base64');
}

function verify (key, msg, hash) {
    return crypto.createVerify('RSA-SHA256')
        .update(msg)
        .verify(key, hash, 'base64')
    ;
}

function frame (key, buf) {
    var h = hash(key, buf);
    
console.dir(h); 
    return buf;
}

function unframe (key, buf) {
    return buf;
}
