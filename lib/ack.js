var inherits = require('inherits');
var EventEmitter = require('events').EventEmitter;

module.exports = Ack;
inherits(Ack, EventEmitter);

function Ack (count) {
    var self = this;
    if (!(self instanceof Ack)) return new Ack(count);
    
    self.count = count;
    if (count === 0) {
        process.nextTick(function () { self.accept() });
    }
}

Ack.prototype.accept = function () {
    if (this.rejected || this.accepted) return;
    if (--this.count > 0) return;
    
    this.accepted = true;
    this.emit('accept');
};
 
Ack.prototype.reject = function () {
    if (this.rejected) return;
    this.rejected = true;
    this.emit('reject');
};
