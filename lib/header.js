var through = require('through');

module.exports = function (cb) {
    var line = '';
    var gotHead = false;
    
    return through(function ondata (buf) {
        if (gotHead) return cb.call(this, buf);
        
        for (var i = 0; i < buf.length; i++) {
            if (buf[i] === 10 || buf[i] === '\n') {
                gotHead = true;
                line += buf.slice(0, i);
                try {
                    var header = JSON.parse(line);
                }
                catch (e) {
                    this.emit('parseError', e);
                    this.emit('close');
                    return;
                }
                this.emit('header', header);
                
                line = undefined;
                ondata(buf.slice(i + 1));
                return;
            }
        }
        line += buf;
    });
};
