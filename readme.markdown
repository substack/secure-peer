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

# protocol

`secure-peer` implements a very simple protocol that gives gives confidential content, although the identity of the peers (pubkeys) are leaked to a passive evesdropper.

The protocol begins by sending a handshake
[code](https://github.com/substack/secure-peer/blob/master/index.js#L163-L174)

``` js
    var outgoing = {
        token : crypto.randomBytes(64).toString('base64'),
        key : {
            type : 'rsa',
            public : keys.public,
        },
        dh : {
            group : dh.group,
            public : dh.getPublicKey('base64')
        },
        ciphers : ciphers
    };
```
The header contains a token (used to prevent replay attacks), your public key, a new diffie-helman public key,
and the list of supported ciphers.

This is then signed with the corresponding private key, and sent as a line of json. [code](https://github.com/substack/secure-peer/blob/master/index.js#L180) All binary values are base64 encoded. 

Upon receiving the remote peer's header, the signature is verified (against their supplied public key), and the `identity` event is emitted. A secure-peer client (i.e. the peer that initiated the connection) should now check that they have achived a connection to the peer they expected to connect to. It would be expected for a server to receive connections from potentially unknown peers.

If all the `identity` listeners call `ack.accept()` then the connection is accepted,
and the secret is derived from the diffie-helman keys.

The cipher is selected by a ordinal voting algorithm. Each peer sends an preference ordered list of supported ciphers. The cipher is picked by selecting the peer with the greatest token, and then using their most preferred token which is also supported by the other peer.

> Security Hole (minor): Since a peer can choose their token "randomly" they can choose particularily high tokens that are highly likely to allow them to pick the cipher. This could be used for a cipher downgrade attack... cipher selection is generally problematic... but this weakness is probably best remedied by some out of band way to make sure the network upgrade cycle is short. It might be better to elect the cipher picking peer by a fair method (where the winner is provably fair, such picking the peer who's token is closest to `hash(p1.token + p2.token)`. Another option might be to allow the server (i.e. person who picked up the phone) to select the cipher since they are in a slightly more vulnerable position (and more likely to be the victum in an attack).

Now, stream packets may be sent to the remote peer. Each packet is framed along with an incrementing sequence number, and the token sent by the remote peer, this prevents replay attacks, because the peer will not accept packets with the wrong token, and prevents reordering attacks, since the peer will not accept replayed packets if the sequence numbers are not in order.

> Security Hole: Although the session cannot be replayed, the initial handshake *can* be replayed. This will cause the server to believe it has established a connection, if the attacker does not send any content then the attack will not be discovered. This could probably be used for a denial of service attack, or maybe to cause the server to leak information via timing, in cases where they implement a protocol that streams realtime data without waiting for the client to send anything.

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
