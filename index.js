var crypto = require('crypto');
var header = require('header-stream');
var through = require('through');

var groups = [
    'modp1', 'modp2', 'modp5', // rfc 2412
    'modp14', 'modp15', 'modp16', 'modp17', 'modp18' // rfc 3526
];

module.exports = function (keys) {
    function hash (payload) {
        var signer = crypto.createSign('RSA-SHA256');
        signer.update(payload);
        return signer.sign(keys.private, 'base64');
    }
    
    return function (cb) {
        var sec = header(through());
        var group = groups[Math.floor(Math.random() * groups.length)];
        var dh = crypto.getDiffieHellman(group);
        dh.generateKeys();
        
        var payload = JSON.stringify({
            rsa : { public : keys.public },
            dh : {
                group : group,
                public : dh.getPublicKey('base64')
            }
        });
        sec.setHeader({ hash : hash(payload), payload : payload });
        
        var counts = { accept : 0, reject : 0 , listen : 0 };
        
        sec.accept = function () {
            counts.accept ++;
            if (counts.reject > 0 || counts.listen !== counts.accept) return;
            
            console.dir(sec.payload);
            console.dir(sec.secret);
            
            //sec.emit('connect', stream);
        };
        
        sec.reject = function () {
            counts.reject ++;
            sec.emit('close');
        };
        
        sec.once('header', function (meta) {
            var payload = JSON.parse(meta.payload);
            var v = crypto.createVerify('RSA-SHA256')
                .update(meta.payload)
                .verify(payload.rsa.public, meta.hash, 'base64')
            ;
            if (!v) return sec.reject();
            
            var k = dh.computeSecret(payload.dh.public, 'base64', 'base64');
            
            sec.secret = k;
            sec.payload = payload;
            
            counts.listen = sec.listeners('header').length;
            if (counts.listen === 0 && counts.reject === 0) {
                counts.listen ++;
                sec.accept();
            }
        });
        
        sec.on('pipe', function () {
            process.nextTick(function () {
                sec.writeHead();
            });
        });
        
        if (typeof cb === 'function') sec.on('connect', cb);
        return sec;
    };
};
