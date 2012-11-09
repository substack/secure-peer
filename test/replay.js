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
var es = require('event-stream');

test('replay attack', function (t) {
    t.plan(1);
    var eve = es.connect(es.split(), through(function (line) {
        // eavesdrop on the messages
console.dir(line);
        this.emit('data', String(line) + '\n');
    }));
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            this.emit('data', String(buf).toUpperCase());
        })).pipe(stream);
    });
    
    var b0 = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) { data += buf });
        stream.on('end', function () {
            t.equal(data, 'BEEP BOOP');
        });
        
        stream.write('beep');
        stream.write(' ');
        stream.end('boop');
    });
    
    var b1 = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) { data += buf });
        stream.on('end', function () {
            t.fail('stream should have been destroyed for tampering');
        });
        
        stream.on('close', function () {
            t.ok(true, 'socket closed for tampering');
        });
        
        stream.write('beep');
        stream.write(' ');
        stream.end('boop');
    });
    
    b1.on('end', function () {
        t.fail('outer stream should have been destroyed');
    });
    
    b1.on('close', function () {
        t.ok(true, 'outer stream closed');
    });
    
    a.pipe(eve).pipe(b0).pipe(a);
});
