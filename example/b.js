var secure = require('secure-peer');
var peer = secure(require('./b.json'));

var net = require('net');
var rawStream = net.connect(5000);

var sec = peer(function (stream) {
    stream.pipe(process.stdout);
    var b = Buffer(256);
    Buffer('beep boop\n').copy(b, 0);
    stream.write(b);
});
sec.pipe(rawStream).pipe(sec);

sec.on('identify', function (id) {
    // you can asynchronously verify that the key matches the known value here
    id.accept();
});
