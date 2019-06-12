const node_openssl = require('node-openssl-cert');
var config = require('../config.js');
const opensslbinpath = config.opensslbinpath; //use full path if not in system PATH

var options = {
	binpath: opensslbinpath
}

module.exports = new node_openssl(options);
