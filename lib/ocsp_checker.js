var openssl = require('./openssl.js');

var maxchain = 5;
var curchain = 0;

module.exports = function() {
	this.getCertFromNetwork = function(netcertoptions, callback) {
		openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
			//if(err) console.log(err);
			//console.log(cmd);
			openssl.getOCSPURI(cert[0], function(err, uri, cmd) {
				//console.log(err);
				//console.log(cmd);
				console.log(uri);
				let leaf = cert[0];
				let ca = cert.splice(1).join('\r\n');
				openssl.queryOCSPServer(ca, leaf, uri, function(err, resp, cmd) {
					console.log(cmd);
					callback(err, resp);
				});
			});
		});	
	}
}