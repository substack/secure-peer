module.exports = function toBuffer (str) {
    return typeof str === 'string'
        ? new Buffer(str, 'binary')
        : str;
};
