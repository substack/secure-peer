var secure = require('../');
var peer = secure(require('./a.json'));
var through = require('through');

var net = require('net');
var server = net.createServer(function (rawStream) {
    var sec = peer(function (stream) {
        stream.pipe(through(function (buf) {
            this.emit('data', String(buf).toUpperCase());
        })).pipe(stream);
    });
    sec.pipe(rawStream).pipe(sec);
});
server.listen(5000);
