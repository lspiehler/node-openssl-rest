var openssl = require('./openssl.js');

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
		openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
			//if(err) console.log(err);
			//console.log(cmd);
			if(err) {
				callback('Failed to download certificate(s) for domain.', false, false);
			} else {
				openssl.getOCSPURI(cert[0], function(err, uri, cmd) {
					//console.log(err);
					//console.log(cmd);
					//console.log(uri);
					if(err) {
						callback(err, false, false);
					} else {
						let leaf = cert[0] + '\n';
						let ca = cert.splice(1).join('\n') + '\n';
						if(cert.splice(1)) {
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
