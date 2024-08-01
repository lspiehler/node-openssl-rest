var openssl = require('./openssl.js');
var openssl2 = require('../lib/openssl2.js');

module.exports = function() {
    var downloadchain = [];
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
						if(downloadchain.length <= maxlength) {
							downloadchain.push(ca);
							getChain(ca, callback);
						} else {
							callback('Too many iterations getting certificate chain', false, false);
						}
					}
				});
				//callback(false, uri);
			} else {
				if(downloadchain.length >= 1) {
					callback(false, downloadchain, false);
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
										getChain(cert.data[0], function(err, chain) {
                                            if(err) {
                                                console.log(err);
                                            } else {
                                                console.log();
                                            }
                                            callback(false, chain, 'test');
                                        });
									} else {
										callback(false, fullchain, cmd);
									}
								});
							}
						});
					}
				});
			}
		});	
	}
}