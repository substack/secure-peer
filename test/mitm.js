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

test('basic mitm attack', function (t) {
    t.plan(4);
    
    var bufNum = 0;
    var attacker = through(function (buf) {
        if (!Buffer.isBuffer(buf)) buf = Buffer(buf);
        
        if (++bufNum > 1) buf[15]++;
        this.emit('data', buf);
    });
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            for (var i = 0; i < buf.length; i++) {
                this.emit('data', String(buf.slice(i, i + 1)).toUpperCase());
            }
        })).pipe(stream);
    });
    
    var b = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) {
            
        });
        stream.on('end', function () {
            t.fail('should have been destroyed');
        });
        
        stream.on('close', function () {
            t.ok(true, 'socket closed for tampering');
        });
        
        stream.write('beep');
        stream.write(' ');
        stream.end('boop');
    });
    
    b.on('end', function () {
        t.fail('outer stream should have been destroyed');
    });
    
    b.on('close', function () {
        t.ok(true, 'outer stream closed');
    });
    
    a.on('identify', function (id) {
        t.equal(id.key.public, keys.b.public);
        id.accept();
    });
    
    b.on('identify', function (id) {
        t.equal(id.key.public, keys.a.public);
        id.accept();
    });
    
    a.pipe(attacker).pipe(b).pipe(a);
});
