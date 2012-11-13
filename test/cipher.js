var test = require('tap').test;
var keys = {
    a : require('./keys/a.json'),
    b : require('./keys/b.json'),
};

var secure = require('../');
var peer = {
    a : secure(keys.a, {
        ciphers : [ 'RC4', 'AES-128-CBC', 'BF-OFB' ]
    }),
    b : secure(keys.b, {
        ciphers : [ 'DES', 'SEED', 'AES-128-CBC', 'CAST5-CBC', 'BF-OFB' ]
    }),
};
var through = require('through');

test('accept a connection', function (t) {
    t.plan(5);
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            this.emit('data', String(buf).toUpperCase());
        })).pipe(stream);
    });
    
    var b = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) { data += buf });
        stream.on('end', function () {
            t.equal(data, 'BEEP BOOP');
        });
        stream.end('beep boop');
    });
    
    a.on('identify', function (id) {
        t.equal(id.key.public, keys.b.public);
        t.equal(id.cipher, 'AES-128-CBC');
        id.accept();
    });
    
    b.on('identify', function (id) {
        t.equal(id.key.public, keys.a.public);
        t.equal(id.cipher, 'AES-128-CBC');
        id.accept();
    });
    
    a.pipe(b).pipe(a);
});
