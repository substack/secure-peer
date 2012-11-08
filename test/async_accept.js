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

test('accept a connection', function (t) {
    t.plan(3);
    
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
        setTimeout(function () {
            id.accept();
        }, 100);
    });
    
    b.on('identify', function (id) {
        t.equal(id.key.public, keys.a.public);
        setTimeout(function () {
            id.accept();
        }, 200);
    });
    
    a.pipe(b).pipe(a);
});
