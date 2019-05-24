var openssl = require('./openssl.js');

var chain = [];
var maxlength = 4

/*fs.readFile('./google.crt', function(err, contents) {
        openssl.getIssuerURI(contents.toString(), function(err, uri, cmd) {
                console.log(uri);
                openssl.downloadIssuer(uri, function(err, cert) {
                        if(err) {
                                console.log(err);
                        } else {
                                console.log(cert);
                        }
                });
        });
});*/

var getChain = function(cert, callback) {
	openssl.getIssuerURI(cert, function(err, uri, cmd) {
		if(uri) {
			//console.log(uri);
			openssl.downloadIssuer(uri, function(err, ca) {
                                if(err) {
                                        callback('Failed to download CA.', false, false);
                                } else {
					//console.log(chain.length);
					if(chain.length <= maxlength) {
                                        	chain.push(ca);
						getChain(ca, callback);
					} else {
						callback('Too many iterations getting certificate chain', false, false);
					}
                                }
                        });
			//callback(false, uri);
		} else {
			if(chain.length >= 1) {
				callback(false, chain, false);
			} else {
				callback('Cannot get issuer from certificate', false, false);
			}
		}
	});
}

module.exports = function() {
	this.getCertFromNetwork = function(netcertoptions, callback) {
		openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
			//if(err) console.log(err);
			//console.log(cmd);
			openssl.getOCSPURI(cert[0], function(err, uri, cmd) {
				//console.log(err);
				//console.log(cmd);
				//console.log(uri);
				let leaf = cert[0];
				let ca = cert.splice(1).join('\r\n');
				openssl.queryOCSPServer(ca, leaf, uri, function(err, resp, cmd) {
					//console.log(cmd);
					callback(err, resp);
				});
			});
		});	
	}
	this.query = function(cert, callback) {
		//openssl.getIssuerURI(cert, function(err, uri, cmd) {
		//	callback(false, uri);
		//});
		openssl.getOCSPURI(cert, function(err, uri, cmd) {
			if(err) {
				//console.log(uri);
				callback('Failed to get OCSP URI from certificate.', false, false);
			} else {
				getChain(cert, function(err, chain) {
					if(err) {
						callback(err, false, false);
					} else {
						openssl.queryOCSPServer(chain, cert, uri, function(err, resp, cmd) {
							if(err) {
								callback(err, false, false);
							} else {
								callback(false, resp, cmd);
							}
						});
					}
				});
			}
		});
	}
}
