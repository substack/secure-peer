var crypto = require('crypto');
var header = require('./lib/header');
var through = require('through');
var createAck = require('./lib/ack');

module.exports = function (keys) {
    function hash (payload) {
        var signer = crypto.createSign('RSA-SHA256');
        signer.update(payload);
        return signer.sign(keys.private, 'base64');
    }
    
    var group = 'modp5';
    var dh = crypto.getDiffieHellman(group);
    dh.generateKeys();
    
    return function (cb) {
        var buffers = [];
        var stream, encrypt, decrypt;
        
        var sec = header(function (buf) {
            if (decrypt) {
                stream.emit('data', decrypt.update(buf));
            }
            else buffers.push(buf)
        });
        
        sec.on('accept', function (ack) {
            var pub = ack.payload.dh.public;
            var k = dh.computeSecret(pub, 'base64', 'base64');
console.log('k=' + k);
            encrypt = crypto.createCipher('aes192', k);
            decrypt = crypto.createDecipher('aes192', k);
            
            stream = through(write, end);
            stream.id = ack;
            
            function write (buf) {
                sec.emit('data', encrypt.update(buf));
            }
            
            function end () {
                sec.emit('data', ecrypt.final());
                sec.emit('end');
                sec.emit('close');
            }
            
            sec.emit('connection', stream);
        });
        
        sec.once('header', function (meta) {
            var payload = JSON.parse(meta.payload);
            
            function verify (msg, hash) {
                return crypto.createVerify('RSA-SHA256')
                    .update(msg)
                    .verify(payload.key.public, hash, 'base64')
                ;
            }
            
            var v = verify(meta.payload, meta.hash);
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
                hash : hash(outgoing),
                payload : outgoing
            }) + '\n');
        }
        
        if (typeof cb === 'function') sec.on('connection', cb);
        return sec;
    };
};
