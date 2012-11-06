var secure = require('secure-peer');
var peer = secure(require('./a.json'));

var net = require('net');
var server = net.createServer(function (rawStream) {
    var sec = peer(function (stream) {
        stream.pipe(stream); // simple echo server
    });
    sec.pipe(rawStream).pipe(sec);
});
server.listen(5000);
