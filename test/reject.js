var test = require('tape');
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

test('reject a connection', function (t) {
    t.plan(5);
    
    var a = peer.a(function (stream) {
        t.fail('got the stream in A');
    });
    
    var b = peer.b(function (stream) {
        stream.on('data', function (buf) {
            t.fail('got data in B somehow');
        });
        stream.on('end', function () {
            t.fail('b should have been destroyed');
        });
        
        stream.on('close', function () {
            t.ok(true, 'stream in b closed');
        });
    });
    
    a.on('close', function () {
        t.ok(true, 'a closed');
    });
    
    b.on('close', function () {
        t.ok(true, 'b closed');
    });
    
    a.on('identify', function (id) {
        t.equal(id.key.public, keys.b.public);
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
