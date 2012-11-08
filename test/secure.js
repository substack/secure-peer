var test = require('tap').test;

var secure = require('../');
var peer = {
    a : secure(require('./keys/a.json')),
    b : secure(require('./keys/b.json')),
};
var through = require('through');

test('accept a connection', function (t) {
    t.plan(1);
    
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

    b.on('identify', function (id) {
        id.accept();
    });

    a.pipe(b).pipe(a);
});
