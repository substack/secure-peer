var test = require('tap').test;
var keys = {
    a : require('./keys/a.json'),
    b : require('./keys/b.json'),
};

var secure = require('../');
var peer = {
    a : secure(keys.a),
    b : secure(keys.b),
};
var through = require('through');

test('multiple chunks on the same tick', function (t) {
    t.plan(3);
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            for (var i = 0; i < buf.length; i++) {
                this.emit('data', String(buf.slice(i, i + 1)).toUpperCase());
            }
        })).pipe(stream);
    });
    
    var b = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) { data += buf });
        stream.on('end', function () {
            t.equal(data, 'BEEP BOOP');
        });
        
        stream.write('beep');
        stream.write(' ');
        stream.end('boop');
    });
    
    a.on('identify', function (id) {
        t.equal(id.key.public, keys.b.public);
        id.accept();
    });
    
    b.on('identify', function (id) {
        t.equal(id.key.public, keys.a.public);
        id.accept();
    });
    
    a.pipe(b).pipe(a);
});
