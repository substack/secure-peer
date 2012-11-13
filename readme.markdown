# secure-peer

Create encrypted peer-to-peer streams using public key cryptography and signing.

No certificates, no authorities. Each side of the connection has the same kind
of keys so it doesn't matter which side initiates the connection.

[![build status](https://secure.travis-ci.org/substack/secure-peer.png)](http://travis-ci.org/substack/secure-peer)

# example

First generate some public/private keypairs with
[rsa-json](http://github.com/substack/rsa-json):

```
$ rsa-json > a.json
$ rsa-json > b.json
```

``` js
var secure = require('secure-peer');
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
```

``` js
var secure = require('secure-peer');
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
```

For extra security, you should keep a file around with known hosts to verify
that the public key you receive on the first connection doesn't change later
on like how `~/.ssh/known_hosts` works.

Maintaining a known hosts file is outside the scope of this module.

# methods

``` js
var secure = require('secure-peer')
```

## var peer = secure(keys, opts={})

Return a function to create streams given the `keys` supplied.

`keys.private` should be a private PEM string and `keys.public` should be a
public PEM string.

You can generate keypairs with [rsa-json](http://github.com/substack/rsa-json).

You can set a preference ordering array of ciphers to use with `opts.ciphers`.
Both sides will use a deterministic ordinal voting algorithm to determine which
cipher to use.
See `openssl list-cipher-algorithms` for the whole list.

## var sec = peer(cb)

Create a new duplex stream `sec` that caries the encrypted contents. This stream
is safe to stream over the wire, including untrusted networks.

`cb` is a shorthand to listen on the `'connection'` event just like
`net.createServer()`.

# events

## sec.on('connection', function (stream) {})

Emitted with the decrypted plaintext stream when the secure connection has been
established successfully.

`stream.id` is the identify object from the `'identify'` event.

## sec.on('identify', function (id) {})

Emitted when the connection identifies with its public key, `id.key`.

Each listener *must* call either `id.accept()` or `id.reject()`.

The connection won't be accepted until all listeners call `id.accept()`. If any
listener calls `id.reject()`, the connection will be aborted.

### id.accept()

Accept the connection. This function must be called for every listener on the
`'identify'` event for the connection to succeed.

### id.reject()

Reject the connection. The connection will not succeed even if `id.accept()` was
called in another listener.

## sec.on('header', function (header) {})

Emitted when the remote side provides a signed header.payload json string signed
with its private key in header.hash.

# install

With [npm](https://npmjs.org) do:

```
npm install secure-peer
```

# license

MIT
