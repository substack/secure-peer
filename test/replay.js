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
    t.plan(3);
    
    var messages = [];
    var eve = es.connect(es.split(), through(function (line) {
        // eavesdrop on the messages
        messages.push(line);
        this.emit('data', String(line) + '\n');
    }));
    
    var msgNum = 0;
    var replay = es.connect(es.split(), through(function (line) {
        var msg = messages.shift();
        
        if (++msgNum === 1) {
            this.emit('data', String(line) + '\n');
        }
        else this.emit('data', String(msg) + '\n');
    }));
    
    var a0 = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            this.emit('data', String(buf).toUpperCase());
        })).pipe(stream);
    });
    
    var a1 = peer.a(function (stream) {
        var ix = 0;
        stream.pipe(through(function (buf) {
            var s = String(buf).split('').map(function (c) {
                return (ix++ % 2) ? c.toLowerCase() : c.toUpperCase();
            }).join('');
            this.emit('data', s);
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
    
    b0.on('end', function () {
        a1.pipe(replay).pipe(b1).pipe(a1);
    });
    
    var b1 = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) { data += buf });
        stream.on('end', function () {
            console.log('/!\\ WARNING /!\\');
            console.log('RECEIVED REPLAYED DATA: ' + data);
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
    
    a0.pipe(eve).pipe(b0).pipe(a0);
});
