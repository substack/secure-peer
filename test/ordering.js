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

test('ordering attack', function (t) {
    t.plan(5);
    
    var messages = [];
    var msgNum = 0;
    var reorder = es.connect(es.split(), through(write, end));
    
    function write (line) {
        if (++msgNum === 1) return this.emit('data', String(line) + '\n');
        
        messages.push(line);
        
        if (msgNum === 4) {
            this.emit('data', messages[2] + '\n'); // 'BOOP'
            this.emit('data', messages[1] + '\n'); // ' '
            this.emit('data', messages[0] + '\n'); // 'BEEP'
            messages = [];
        }
        else if (msgNum > 4) {
            this.emit('data', messages.shift() + '\n');
        }
    }
    
    function end () {
        messages.forEach(function (msg) {
            this.emit('data', msg + '\n');
        }.bind(this));
        
        this.emit('end');
    }
    
    var expected = [ 'beep', ' ', 'boop' ];
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            t.equal(String(buf), expected.shift());
            this.emit('data', String(buf).toUpperCase());
        })).pipe(stream);
    });
    
    var b = peer.b(function (stream) {
        var messages = [];
        stream.on('data', function (buf) {
            messages.push(String(buf));
        });
        stream.on('end', function () {
            console.log(
                'WARNING! REORDERED MESSAGES: '
                + JSON.stringify(messages)
            );
            t.fail('stream should have been destroyed');
        });
        
        stream.on('close', function () {
            t.ok(true, 'stream was destroyed');
        });
        
        stream.write('beep');
        stream.write(' ');
        stream.end('boop');
    });
    
    b.on('end', function () {
        t.fail('outer stream should have been destroyed');
    });
    
    b.on('close', function () {
        t.ok(true, 'outer stream was destroyed');
    });
    
    a.pipe(reorder).pipe(b).pipe(a);
});
