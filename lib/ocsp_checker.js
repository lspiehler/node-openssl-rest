var openssl = require('./openssl.js');
var openssl2 = require('../lib/openssl2.js');
const moment = require('moment');

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

var getChainInfo = function(chain, chaindata, index, callback) {
    let begin = 0;
    if(index) {
        begin = index;
    }
    if(begin <= chain.length - 1) {
        openssl.getCertInfo(chain[begin], function(err, certinfo, cmd) {
            if(err) {
                callback(err, false);
            } else {
                chaindata.push(certinfo);
                //console.log(certinfo);
                getChainInfo(chain, chaindata, index + 1, callback);
            }
        });
    } else {
        callback(false, chaindata);
    }
}

var getCertIndexFromChain = function(certissuer, chaindata) {
    for(let i = 0; i <= chaindata.length - 1; i++) {
        if(orderSubject(certissuer)==orderSubject(chaindata[i].attributes['Subject String'])) {
            return i;
        }
    }
    return false;
}

var checkChainOrder = function(chain, callback) {
    //console.log(chain);
    let orderedchain = [];
    getChainInfo(chain, [], 0, function(err, chaindata) {
        if(err) {
            console.log(err);
        } else {
            //console.log(chaindata);
            //var root;
			orderedchain.push(chain[0]);
            openssl.getCertInfo(chain[0], function(err, certinfo, cmd) {
                if(err) {
                    callback(err, false);
                } else {
                    var issuerindex = getCertIndexFromChain(certinfo.attributes.Issuer, chaindata);
                    //console.log(issuerindex);
                    if(issuerindex===false) {
                        callback('Invalid Chain', false);
                        return;
                    }   else {
                        orderedchain.push(chain[issuerindex]);
                    }
                    //let chainindex = 0;
                    while(chaindata[issuerindex].attributes.Issuer!=chaindata[issuerindex].attributes['Subject String']) {
                        issuerindex = getCertIndexFromChain(chaindata[issuerindex].attributes.Issuer, chaindata);
                        //console.log(issuerindex);
                        if(issuerindex===false) {
                            //callback('Invalid Chain', false);
                            //return;
							break;
                        }   else {
                            orderedchain.push(chain[issuerindex]);
                        }
                    }
                    callback(false, orderedchain);
                }
            });
        }
    });
}

var orderSubject = function(subjectstr) {
    let subjarr = subjectstr.split(',');
    for(let i = 0; i < subjarr.length; i++) {
        subjarr[i] = subjarr[i].trim();
    }
    subjarr.sort();
    //console.log(subjarr);
    return subjarr.join(", ");
}

module.exports = function() {

	var chain = [];
	var maxlength = 4

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

	var query = function(cert, callback) {
		//openssl.getIssuerURI(cert, function(err, uri, cmd) {
		//	callback(false, uri);
		//});
		openssl2.x509.parse({cert: cert}, function(err, parsed) {
			if(err) {
				callback('Failed to parse downloaded certificate.', false, false);
			} else {
				var now = moment().utc();
				let startdate = moment(parsed.data.attributes['Not Before']);
				let enddate = moment(parsed.data.attributes['Not After']);
				if(now.diff(startdate, 'seconds') < 0) {
					callback('The certificate is not valid until ' + startdate.toDate() + '.', false, false);
					return;
				}
				if(now.diff(enddate, 'seconds') > 0) {
					callback('The certificate expired on ' + enddate.toDate() + '.', false, false);
					return;
				}
				openssl2.x509.getOCSPURI(cert, function(err, uri, cmd) {
					//console.log(uri);
					if(err) {
						//console.log('test');
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
								openssl2.ocsp.query({cacert: normchain.join('\n') + '\n', cert: cert, uri: uri.data, hash: 'sha1'}, function(err, resp) {
									if(err) {
										callback(err, false);
									} else {
										callback(false, resp);
									}
								});
							}
						});
					}
				});
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
		netcertoptions.sigalgs = [
			"ECDSA+SHA256",
			"ECDSA+SHA384",
			"ECDSA+SHA512",
			"ed25519",
			"ed448",
			"RSA-PSS+SHA256",
			"RSA-PSS+SHA384",
			"RSA-PSS+SHA512",
			"rsa_pss_rsae_sha256",
			"rsa_pss_rsae_sha384",
			"rsa_pss_rsae_sha512",
			"RSA+SHA256",
			"RSA+SHA384",
			"RSA+SHA512",
			"ECDSA+SHA224",
			"RSA+SHA224",
			"DSA+SHA224",
			"DSA+SHA256",
			"DSA+SHA384",
			"DSA+SHA512"
		];
		openssl2.x509.getCertFromNetwork(netcertoptions, function(err, cert) {
			//if(err) console.log(err);
			if(err) {
				callback('Failed to download certificate(s) for domain.', false, false);
			} else {
				openssl2.x509.parse({cert: cert.data[0]}, function(err, parsed) {
					if(err) {
						callback('Failed to parse downloaded certificate.', false, false);
					} else {
						var now = moment().utc();
						let startdate = moment(parsed.data.attributes['Not Before']);
						let enddate = moment(parsed.data.attributes['Not After']);
						if(now.diff(startdate, 'seconds') < 0) {
							callback('The certificate is not valid until ' + startdate.toDate() + '.', false, false);
							return;
						}
						if(now.diff(enddate, 'seconds') > 0) {
							callback('The certificate expired on ' + enddate.toDate() + '.', false, false);
							return;
						}
						var fullchain = cert.data.slice();
						//console.log(fullchain);
						openssl2.x509.getOCSPURI(cert.data[0], function(err, uri, cmd) {
							//console.log(err);
							//console.log(cmd);
							//console.log(uri);
							if(err) {
								callback(err, false, false);
							} else {
								//console.log(cert.data.splice(1));
								checkChainOrder(fullchain, function(err, chain) {
									if(err) {
										//callback(err, false, false);
										//if chain is messed up, try getting the chain from the AIA info on the cert
										console.log('Chain error. Trying to get chain from AIA on the cert');
										query(cert.data[0], function(err, resp, cmd) {
											if(err) {
												callback(err, false, false);
											} else {
												callback(false, resp, cmd);
											}
										});
									} else {
										//console.log('here');
										let leaf = chain[0] + '\n';
										let ca = chain.splice(1).join('\n') + '\n';
										//console.log(chain[0]);
										//console.log(chain.splice(1));
										openssl2.ocsp.query({cacert: ca, cert: chain[0], uri: uri.data, hash: 'sha1'}, function(err, resp) {
										//openssl.queryOCSPServer(ca, chain[0], uri.data, 'sha1', false, function(err, resp, cmd) {
											if(err) {
												callback(err, false);
											} else {
												callback(false, resp);
											}
										});
									}
								});
							}
						});
					}
				});
			}
		});	
	}
	this.query = function(cert, callback) {
		query(cert, function(err, resp, cmd) {
			callback(err, resp, cmd);
		});
	}
}
