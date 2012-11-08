var secure = require('../');
var peer = secure(require('./b.json'));

var net = require('net');
var rawStream = net.connect(5000);

var sec = peer(function (stream) {
    stream.pipe(process.stdout);
    stream.end('beep boop\n');
});
sec.pipe(rawStream).pipe(sec);

sec.on('identify', function (id) {
    // you can asynchronously verify that the key matches the known value here
    id.accept();
});
