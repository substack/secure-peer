module.exports = function (xs_, ys_) {
    // ordinal voting
    var votes = {};
    var xs = xs_.filter(function (x) { return ys_.indexOf(x) >= 0 });
    var ys = ys_.filter(function (y) { return xs_.indexOf(y) >= 0 });
    
    vote(xs); vote(ys);
    
    function vote (vs) {
        vs.forEach(function (v, i) {
            votes[v] = (votes[v] || 0) + (i + 1) / vs.length;
        });
    }
     
    return Object.keys(votes).sort().reduce(function (min, key) {
        if (!min || votes[key] < votes[min]) min = key
        return min;
    }, null);
};
