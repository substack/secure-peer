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
    t.plan(3);
    
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
    
    var a = peer.a(function (stream) {
        stream.pipe(through(function (buf) {
            this.emit('data', String(buf).toUpperCase());
        })).pipe(stream);
    });
    
    var b = peer.b(function (stream) {
        var data = '';
        stream.on('data', function (buf) {
            data += buf
        });
        stream.on('end', function () {
            console.dir([ 'END', data ]);
        });
        
        stream.write('beep');
        stream.write(' ');
        stream.end('boop');
    });
    
    a.pipe(reorder).pipe(b).pipe(a);
});
