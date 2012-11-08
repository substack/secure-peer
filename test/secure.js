var test = require('tap').test;
var secure = require('secure-peer');
var through = require('through');

var peer = {
    a : secure(require('./keys/a.json')),
    b : secure(require('./keys/b.json')),
};

test('accept a secure connection', function (t) {
    t.plan(1);
    t.on('end', function () {
        console.log('...');
    });
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
console.dir(buf); 
            this.emit('data', String(buf).toUpperCase());
        }).pipe(stream));
    });
    
    var b = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) {
console.dir(String(buf)); 
            data += buf;
        });
        stream.on('end', function () {
            t.equal(data, 'BEEP BOOP\n');
        });
        stream.write('beep boop\n');
    });
    
    a.on('identify', function (id) {
        id.accept();
    });
    
    b.on('identify', function (id) {
        id.accept();
    });
    
    a.pipe(b).pipe(a);
});
