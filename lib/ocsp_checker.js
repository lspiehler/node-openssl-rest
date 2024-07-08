var openssl = require('./openssl.js');
var openssl2 = require('../lib/openssl2.js');

//var chain = [];
//var maxlength = 4

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

/*var getChain = function(cert, callback) {
	openssl.getIssuerURI(cert, function(err, uri, cmd) {
		if(uri) {
			//console.log(uri);
			openssl.downloadIssuer(uri, function(err, ca) {
                                if(err) {
                                        callback('Failed to download CA.', false, false);
                                } else {
					console.log(chain.length);
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
}*/

module.exports = function() {

	var chain = [];
	var maxlength = 4

	var getChain = function(cert, callback) {
        openssl.getIssuerURI(cert, function(err, uri, cmd) {
                if(uri) {
                        //console.log(uri);
                        openssl.downloadIssuer(uri, function(err, ca) {
							//console.log(ca);
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


	this.getCertFromNetwork = function(netcertoptions, callback) {
		netcertoptions.groups = [
			"x25519",
			"secp256r1",
			"x448",
			"secp521r1",
			"secp384r1",
			"ffdhe2048",
			"ffdhe3072",
			"ffdhe4096",
			"ffdhe6144",
			"ffdhe8192",
			"prime256v1"
		];
		openssl2.x509.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
			//if(err) console.log(err);
			//console.log(cmd);
			if(err) {
				callback('Failed to download certificate(s) for domain.', false, false);
			} else {
				openssl.getOCSPURI(cert.data[0], function(err, uri, cmd) {
					//console.log(err);
					//console.log(cmd);
					//console.log(uri);
					if(err) {
						callback(err, false, false);
					} else {
						let leaf = cert.data[0] + '\n';
						let ca = cert.data.splice(1).join('\n') + '\n';
						if(cert.data.splice(1)) {
							openssl.queryOCSPServer(ca, leaf, uri, 'sha1', false, function(err, resp, cmd) {
								if(err) {
									callback(err, resp, cmd);
								} else {
									callback(false, resp, cmd);
								}
							});
						} else {
							callback(err, false, false);
						}
					}
				});
			}
		});	
	}
	this.query = function(cert, callback) {
		//openssl.getIssuerURI(cert, function(err, uri, cmd) {
		//	callback(false, uri);
		//});
		//console.log(cert);
		openssl.getOCSPURI(cert, function(err, uri, cmd) {
			//console.log(uri);
			if(err) {
				//console.log(uri);
				callback('Failed to get OCSP URI from certificate.', false, false);
			} else {
				getChain(cert, function(err, chain) {
					if(err) {
						callback(err, false, false);
					} else {
						var normchain = [];
						for(let i = 0; i <= chain.length - 1; i++) {
							let normalize1 = chain[i].trim('\r\n');
							let normalize2 = normalize1.trim('\n');
							normchain.push(normalize2);
						}
						//console.log(normchain.join('\n') + '\n');
						openssl.queryOCSPServer(normchain.join('\n') + '\n', cert, uri, 'sha1', false, function(err, resp, cmd) {
							//if(err) {
								//console.log(resp);
								//callback(err, false, false);
							//} else {
								callback(false, resp, cmd);
							//}
						});
					}
				});
			}
		});
	}
}
