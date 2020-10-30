module.exports = function () {
    let obj = require('bindings')('cryptoforknote.node')();
    return obj;
};

