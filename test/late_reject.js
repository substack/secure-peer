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

test('reject a connection after accepting it', function (t) {
    t.plan(6);
    
    var a = peer.a(function (stream) {
        stream.write('beep');
        
        setTimeout(function () {
            stream.end(' boop');
        }, 300);
    });
    
    var b = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) { data += buf });
        
        stream.on('end', function () {
            t.fail('b should have been destroyed');
        });
        
        stream.on('close', function () {
            t.ok(true, 'stream in b closed');
            t.equal(data, 'beep');
        });
    });
    
    a.on('end', function () {
        t.fail('a should have been destroyed');
    });
    
    a.on('close', function () {
        t.ok(true, 'a closed');
    });
    
    b.on('end', function () {
        t.fail('b should have been destroyed');
    });
    
    b.on('close', function () {
        t.ok(true, 'b closed');
    });
    
    a.on('identify', function (id) {
        t.equal(id.key.public, keys.b.public);
        id.accept();
        
        setTimeout(function () {
            id.reject();
        }, 200);
    });
    
    b.on('identify', function (id) {
        t.equal(id.key.public, keys.a.public);
        setTimeout(function () {
            id.accept();
        }, 50);
    });
    
    a.pipe(b).pipe(a);
});
