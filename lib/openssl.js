const node_openssl = require('node-openssl-cert');

var options = {
	binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
}

module.exports = new node_openssl();
