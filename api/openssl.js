var express = require('express'), 
router = express.Router();
var openssl = require('../lib/openssl.js');
var openssl2 = require('../lib/openssl2.js');
var ocspcache = require('../lib/ocspcache.js');
var multer  = require('multer')
var upload = multer();
var fs = require('fs');
var config = require('../config.js');
var email = require('../email.js');
const opensslbinpath = config.opensslbinpath; //use full path if not in system PATH
const nodemailer = require('nodemailer');
const { spawn } = require( 'child_process' );
var md5 = require('md5');
var ocsplib = require('../lib/ocsp_checker.js');
var decoderlib = require('../lib/certificate_decoder.js');
const https = require('node:https');
const moment = require('moment');

/*var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}*/

var fileExists = function(path, callback) {
	fs.stat(path, function(err, stat) {
		if(err == null) {
			callback(false, stat);
		} else if(err.code == 'ENOENT') {
			callback(true, false);
		} else {
			callback(err, false);
		}
	});
}

var runOpenSSLCommand = function(cmd, cwd, callback) {
	const stdoutbuff = [];
	const stderrbuff = [];
	
	//console.log(cmd);
	
	const openssl = spawn( opensslbinpath, cmd.split(' '), {cwd: cwd} );
	
	openssl.stdout.on('data', function(data) {
		stdoutbuff.push(data.toString());
		/*//openssl.stdin.setEncoding('utf-8');
		setTimeout(function() {
			//openssl.stdin.write("QUIT\r");
			//console.log('QUIT\r\n');
			//openssl.stdin.end();
			openssl.kill();
		}, 1000);*/
	});

	/*openssl.stdout.on('end', function(data) {
		stderrbuff.push(data.toString());
	});*/
	
	openssl.stderr.on('data', function(data) {
		stderrbuff.push(data.toString());
	});
	
	openssl.on('exit', function(code) {
		var out = {
			command: 'openssl ' + cmd,
			stdout: stdoutbuff.join(''),
			stderr: stderrbuff.join(''),
			exitcode: code
		}
		if (code != 0) {
			callback(stderrbuff.join(), out);
		} else {
			callback(false, out);
		}
	});
}

var getCADir = function(req) {
	let cadir;
	//console.log(req.headers);
	if(config.caIPDir) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		cadir = './ca/' + md5(ip);
		return cadir;
	} else {
		cadir = './ca/global';
		return cadir;
	}
}

var revokeCerts = function(cadir, caname, revoke, index, callback) {
	fs.stat(cadir + '/' + caname + '/certs/' + revoke[index] + '.pem', function(err, stat) {
		if(err == null) {
			fileExists(cadir + '/' + caname + '/capass.txt', function(err, stat) {
				let cmd;
				if(err) {
					cmd = 'ca -config config.txt -revoke certs/' + revoke[index] + '.pem';
				} else {
					cmd = 'ca -config config.txt -passin file:capass.txt -revoke certs/' + revoke[index] + '.pem';
				}
				//console.log('Issuer lookup for ' + caname + ', DER exists');
				runOpenSSLCommand(cmd, cadir + '/' + caname, function(err, out) {
					if(err) {
						
					} else {
						
					}
					if(index >= revoke.length - 1) {
						callback(false, false);
					} else {
						revokeCerts(cadir, caname, revoke, index + 1, callback);
					}
					//console.log(out);
				});
			});
		} else if(err.code == 'ENOENT') {
			// file does not exist
			//console.log('does not exist');
			callback(cadir + '/' + caname + '/certs/' + revoke[index] + '.pem does not exist', cadir + '/' + caname + '/certs/' + revoke[index] + '.pem does not exist');
		} else {
			//console.log('Some other error: ', err.code);
			callback(cadir + '/' + caname + '/certs/' + revoke[index] + '.pem error', cadir + '/' + caname + '/certs/' + revoke[index] + '.pem error');
		}
	});
}

router.post('/decodeCert', function(req, res) {
	//console.log(req.body);
	res.json(req.body);
});

router.post('/revokeCerts', function(req, res) {
	//console.log(req.body);
	var cadir = getCADir(req);
	let caname = req.body.ca.replace(/_/g, " ");
	//console.log(caname);
	revokeCerts(cadir, caname, req.body.revoke, 0, function(err, msg) {
		if(err) {
			res.json(err);
		} else {
			ocspcache.clearCache();
			fs.unlink(cadir + '/' + caname + '/ca.crl', function(err) {
				res.json(false);
			});
		}
	});
	/*fs.stat(cadir + '/' + caname + '/certs/' + req.body.revoke[0] + '.pem', function(err, stat) {
		if(err == null) {
			console.log('Issuer lookup for ' + caname + ', DER exists');
		} else if(err.code == 'ENOENT') {
			// file does not exist
			//console.log('does not exist');
			res.json(false);
		} else {
			//console.log('Some other error: ', err.code);
			res.json(false);
		}
	});*/
});

router.get('/clearCache', function(req, res) {
	ocspcache.clearCache();
	res.json({
		error: false,
		message: 'cache cleared'
	});
});

router.get('/issuedCert/:ca/:cert', function(req, res) {
	let cadir = getCADir(req);
	fs.stat(cadir + '/' + req.params.ca + '/certs/' + req.params.cert.replace('.crt','.pem'), function(err, stat) {
		if(err == null) {
			fs.readFile(cadir + '/' + req.params.ca + '/certs/' + req.params.cert.replace('.crt','.pem'), function(err, pem) {
				var mimetype = 'application/pkix-cert';
				res.setHeader('Content-disposition', 'attachment; filename=' + req.params.cert);
				res.setHeader('Content-type', mimetype);
				res.charset = 'UTF-8';
				//console.log(command);
				res.send(pem);
			});
		} else if(err.code == 'ENOENT') {
			//res.json(false);
		} else {
			//console.log('Some other error: ', err.code);
			//res.json(false);
		}
	});
});

router.get('/getCAs', function(req, res) {
	let CAs = [];
	let cadir = getCADir(req);
	//console.log(cadir);
	fs.stat(cadir, function(err, stat) {
		if(err == null) {
			fs.readdir(cadir, function (err, files) {
				files.forEach(file => {
					//let splitfile = file.split('.');
					//console.log(file);
					//console.log(splitfile[splitfile.length - 1]);
					//if(splitfile[splitfile.length - 1].toUpperCase()=='CRT') {
					//console.log(file.substring(0, 2));
					if(fs.statSync(cadir + '/' + file).isDirectory()) {
						ca = {
							name: file
						}
						CAs.push(ca);
					}
					//if(file.isDirectory()) {	
						//splitfile.pop()
					//	CAs.push(file.join(''));
					//}
				});
				var hash = false;
				if(config.caIPDir) {
					let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
					hash = md5(ip) + '/';
				}
				res.json({
					cas: CAs,
					hash: hash,
					publichttp: config.publichttp.replace('http://', '')
				});
				return;
			})
		} else if(err.code == 'ENOENT') {
			// file does not exist
			//console.log('does not exist');
			res.json(false);
		} else {
			//console.log('Some other error: ', err.code);
			res.json(false);
		}
	});
});

router.post('/showIssuedCerts', function(req, res) {
	let CAs = [];
	let cadir = getCADir(req);
	var data = { error: true, issuedcerts: []};
	//console.log(cadir);
	fs.stat(cadir + '/' + req.body.ca + '/index.txt', function(err, stat) {
		if(err == null) {
			fs.readFile(cadir + '/' + req.body.ca + '/index.txt', function(err, file) {
				var certs = file.toString().split('\n');
				for(var i = 0; i <= certs.length - 1; i++) {
					var attrs = certs[i].trim('\r').split('\t');
					//console.log(attrs.length);
					if(attrs.length >= 6) {
						var cert = {
							validity: attrs[0],
							expiration: new Date(attrs[1].substr(0, 4) + '-' + attrs[1].substr(4, 2) + '-' + attrs[1].substr(6, 2) + ' ' + attrs[1].substr(8, 2) + ':' + attrs[1].substr(10, 2) + ':' + attrs[1].substr(12, 2)),
							serial: attrs[3],
							ca: attrs[4],
							subject: attrs[5]
						};
						if(cert.subject!='/CN=OCSP') {
							data.issuedcerts.push(cert);
						}
						//console.log(attrs);
					}
				}
				data.error = false;
				res.json(data);
			});
		} else if(err.code == 'ENOENT') {
			// file does not exist
			//console.log('does not exist');
			res.json(data);
		} else {
			//console.log('Some other error: ', err.code);
			res.json(data);
		}
	});
});

router.post('/postFeedback', function(req, res) {
	console.log(req.body);
	let usagedata = {
		action: 'Feedback',
		message: req.body.message
	}
	usageData(usagedata);
	res.json(true);
});

router.get('/getAvailableCurves', function(req, res) {
	openssl.getAvailableCurves(function(err, curves, out) {
		if(err) {
			res.json(false);
		} else {
			res.json(curves);
		}
	});
});

router.get('/issuer/:ca', function(req, res) {
	let cadir = getCADir(req);
	fs.stat(cadir + '/' + req.params.ca + '/ca.der', function(err, stat) {
		if(err == null) {
			fs.readFile(cadir + '/' + req.params.ca + '/ca.crt', function(err, der) {
				var mimetype = 'application/x-x509-ca-cert';
				res.setHeader('Content-disposition', 'attachment; filename=' + req.params.ca + '.cer');
				res.setHeader('Content-type', mimetype);
				res.charset = 'UTF-8';
				//console.log(command);
				res.send(der);
			});
		} else if(err.code == 'ENOENT') {
			console.log('false');
			fs.stat(cadir + '/' + req.params.ca + '/ca.crt', function(err, stat) {
				if(err == null) {
					//console.log('here');
					fs.readFile(cadir + '/' + req.params.ca + '/ca.crt', function(err, data) {
						openssl.convertPEMtoDER(data, function(err, der, cmd){
							fs.writeFile(cadir + '/' + req.params.ca + '/ca.der', der, function(err) {
								var mimetype = 'application/x-x509-ca-cert';
								res.setHeader('Content-disposition', 'attachment; filename=' + req.params.ca + '.cer');
								res.setHeader('Content-type', mimetype);
								res.charset = 'UTF-8';
								//console.log(command);
								res.send(der);
							});
						});
					});
				} else {
					//console.log('here');
					res.status(404);
					res.send('CA does not exist');
				}
			});
			// file does not exist
			//console.log('does not exist');
			//res.json(false);
		} else {
			//console.log('Some other error: ', err.code);
			//res.json(false);
		}
	});
});

var convertCertToCSR = function(download, certs, index, callback) {
	//console.log(index);
	openssl.convertCertToCSR(certs[index], function(err,csr,cmd) {
		if(err) {
			//console.log(err);
			callback("Unable to download certificates.", download, cmd);
		} else {
			var cert = {
				cert: certs[index],
				options: csr
			}
			download.push(cert);
			if(index==certs.length - 1) {
				callback(err, download, cmd);
				//console.log(csroptions);
				return;
			} else {
				convertCertToCSR(download, certs, index + 1, callback);
			}
		}
	});
}

router.post('/getCertFromNetwork', function(req, res) {
	var netcertoptions = req.body;
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
    ]
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
	var command = [];
	//console.log(netcertoptions);
	openssl2.x509.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
		if(err) {
			var data = {
				error: err,
				csroptions: cert.data
			}
			res.json(data);
			return;
		} else {
			var certs = [];
			convertCertToCSR(certs, cert.data, 0, function(err, csroptions, cmd) {
				let usagedata = {
					action: 'ImportedCertificate',
					err: err,
					headers: req.headers,
					certs: csroptions
				}
				usageData(usagedata);
				//console.log(JSON.stringify(csroptions, null, 4));
				if(err) {
					var data = {
						error: err,
						csroptions: csroptions,
						command: command
					}
				} else {
					var data = {
						error: err,
						csroptions: csroptions,
						command: command
					}
				}
				res.json(data);
			});
			/*openssl.convertCertToCSR(cert[0], function(err,csroptions,cmd) {
				command.push(cmd);
				if(err) {
					var data = {
						error: err,
						csroptions: csroptions,
						command: command
					}
				} else {
					var data = {
						error: err,
						csroptions: csroptions,
						command: command
					}
				}
				//console.log(data);
				res.json(data);
			});*/
		}
	});
});

router.post('/getCSRFromCert', function(req, res) {
	var cert = req.body.cert;
	openssl.convertCertToCSR(cert, function(err,csroptions,cmd) {
		//command.push(cmd);
		if(err) {
			var data = {
				error: err,
				csroptions: csroptions,
				command: cmd
			}
		} else {
			var data = {
				error: err,
				csroptions: csroptions,
				command: cmd
			}
		}
		//console.log(data);
		res.json(data);
	});
});

router.post('/returnDownload', function(req, res) {
	//console.log(req.body);
	var mimetype;
	switch(req.body.filename.split('.')[1]) {
		case "key":
			mimetype = 'application/pkcs8';
			break;
		case "csr":
			mimetype = 'application/pkcs10';
			break;
		case "crt":
			mimetype = 'application/x-x509-user-cert';
			break;
		default:
			mimetype = 'text/plain';
	}
	res.setHeader('Content-disposition', 'attachment; filename=' + req.body.filename);
	res.setHeader('Content-type', mimetype);
	res.charset = 'UTF-8';
	res.send(req.body.data);
});

router.post('/downloadPFX', function(req, res) {
	//console.log(req.body);
	openssl.createPKCS12(req.body.crt, req.body.key, req.body.passin, req.body.passout, false, function(err, pfx, command) {
		if (err) console.log(err);
		var mimetype = 'application/x-pkcs12';
		res.setHeader('Content-disposition', 'attachment; filename=cert.pfx');
		res.setHeader('Content-type', mimetype);
		res.charset = 'UTF-8';
		//console.log(command);
		res.send(pfx);
	});
});

router.post('/downloadPKCS7', function(req, res) {
	//console.log(req.body);
	var certs = [];
	for(var key in req.body) {
		certs.push(req.body[key]);
	}
	openssl.createPKCS7(certs, 'PEM', function(err, pkcs7, command) {
		if (err) console.log(err);
		var mimetype = 'application/x-pkcs7-certificates';
		res.setHeader('Content-disposition', 'attachment; filename=cert.p7b');
		res.setHeader('Content-type', mimetype);
		res.charset = 'UTF-8';
		//console.log(command);
		//console.log(pkcs7);
		res.send(pkcs7);
	});
});

router.post('/uploadPrivateKey', upload.single('file'), function(req, res) {
	//console.log(req.file);
	if(req.body.password=='false' || req.body.password==false) {
		var password = false;
	} else {
		var password = req.body.password;
	}
	var key = req.file.buffer;
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.importRSAPrivateKey(key, password, function(err, key, cmd) {
		if(err) {
			var data = {
				error: err,
				key: key
			}
		} else {
			var data = {
				error: false,
				key: key
			}
		}
		res.send(data);
	});
});

router.post('/uploadECCPrivateKey', upload.single('file'), function(req, res) {
	//console.log(req.file);
	if(req.body.password=='false' || req.body.password==false) {
		var password = false;
	} else {
		var password = req.body.password;
	}
	var key = req.file.buffer;
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.importECCPrivateKey(key, password, function(err, key, cmd) {
		if(err) {
			var data = {
				error: err,
				key: key
			}
		} else {
			var data = {
				error: false,
				key: key
			}
		}
		res.send(data);
	});
});

router.post('/checkCAKey', function(req, res) {
	//console.log(req.file);
	let cadir = getCADir(req);
	if(req.body.password=='false' || req.body.password==false) {
		var password = false;
	} else {
		var password = req.body.password;
	}
	var capath = req.body.ca;
	fs.readFile(cadir + '/' + capath + '/ca.crt', function(err, crtdata) {
		openssl.getCertInfo(crtdata, function(err,data,cmd) {
			//console.log(data);
			if(err) {
				fs.readFile(cadir + '/' + capath + '/ca.key', function(err, keydata) {
					//console.log(keydata);
					openssl.importRSAPrivateKey(keydata, password, function(err, key, cmd) {
						//console.log(key);
						if(err) {
							var keydata = false;
						} else {
							var keydata = {
								path: capath
							}
						}
						res.send(keydata);
					});
				});
			} else {
				if(data['attributes']['Public Key Algorithm'].toLowerCase().indexOf('ec') >= 0) {
					fs.readFile(cadir + '/' + capath + '/ca.key', function(err, keydata) {
						//console.log(keydata);
						openssl.importECCPrivateKey(keydata, password, function(err, key, cmd) {
							//console.log(key);
							if(err) {
								var keydata = false;
							} else {
								var keydata = {
									path: capath
								}
							}
							res.send(keydata);
						});
					});
				} else if(data['attributes']['Public Key Algorithm'].toLowerCase().indexOf('rsa') >= 0) {
					fs.readFile(cadir + '/' + capath + '/ca.key', function(err, keydata) {
						//console.log(keydata);
						openssl.importRSAPrivateKey(keydata, password, function(err, key, cmd) {
							//console.log(key);
							if(err) {
								var keydata = false;
							} else {
								var keydata = {
									path: capath
								}
							}
							res.send(keydata);
						});
					});
				} else {
					fs.readFile(cadir + '/' + capath + '/ca.key', function(err, keydata) {
						//console.log(keydata);
						openssl2.keypair.importOQSKey({key: keydata, password: password}, function(err, key, cmd) {
							//console.log(key);
							if(err) {
								var keydata = false;
							} else {
								var keydata = {
									path: capath
								}
							}
							res.send(keydata);
						});
					});
				}
			}
		});
	});
	//var username = req.body.username;
	//var password = req.body.password;
});

router.post('/generateRSAPrivateKey', function(req, res) {
	sendRequestToOS('key', req, function(err, result){});
	var rsakeyoptions = req.body;
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
		if(err) {
			var data = {
				error: err,
				key: key,
				command: cmd
			}
		} else {
			var data = {
				error: false,
				key: key,
				command: cmd
			}
		}
		res.json(data);
	});
});

router.post('/generateOQSPrivateKey', function(req, res) {
	sendRequestToOS('key', req, function(err, result){});
	var keyoptions = req.body;
	//var username = req.body.username;
	//var password = req.body.password;
	//console.log(keyoptions);
	openssl2.keypair.generateOQSKey(keyoptions, function(err, key) {
		//console.log(err);
		if(err) {
			var data = {
				error: err,
				key: key.data,
				command: key.command
			}
		} else {
			var data = {
				error: false,
				key: key.data,
				command: key.command
			}
		}
		res.json(data);
	});
});

function sendRequestToOS(index, req, callback) {
	if(config.opensearchhost) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		let body = JSON.parse(JSON.stringify(req.body));
		//body['type'] = type;
		let now = moment();
		if(body.hasOwnProperty('key')) {
			delete body.key;
		}
		if(body.hasOwnProperty('ca')) {
			delete body.ca;
		}
		if(body.hasOwnProperty('csr')) {
			delete body.csr;
		}
		body['timestamp'] = now.format('YYYY-MM-DDTHH:mm:ss');
		body['ip'] = ip;
		body['Referer'] = req.headers.referer || '';
		body['User-Agent'] = req.headers['user-agent'] || '';
		body['url'] = req.url;
		//console.log(req)
		const options = {
			options: {
				hostname: config.opensearchhost,
				port: config.opensearchport,
				path: '/' + index + '-' + now.format('YYYY-MM-DD') + '/_doc',
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-ndjson'
				}
				//sigalgs: 'ECDSA+SHA256,ECDSA+SHA384,ECDSA+SHA512,ed25519,ed448,RSA-PSS+SHA256,RSA-PSS+SHA384,RSA-PSS+SHA512,rsa_pss_rsae_sha256,rsa_pss_rsae_sha384,rsa_pss_rsae_sha512,RSA+SHA256,RSA+SHA384,RSA+SHA512,ECDSA+SHA224,RSA+SHA224,DSA+SHA224,DSA+SHA256,DSA+SHA384,DSA+SHA512'
			},
			body: body
		};
		httpRequest2(options, function(err, httpresponse) {
			if(err) {
				callback(err, false);
			} else {
				callback(false, httpresponse);
				console.log(httpresponse);
			}
		});
	} else {
		callback(false, false);
	}
}

router.post('/PQCTest', function(req, res) {
	sendRequestToOS('pqc', req, function(err, result){});
	console.log('PQC test for: ' + req.body.hostname + ':' + req.body.port);
	testPostQuantum(req.body, function(pqerr, pqcresult) {
		if(pqerr) {
			res.json({
				error: pqerr
			});
		} else {
			const options = {
				hostname: req.body.hostname,
				port: req.body.port,
				path: '/',
				method: 'GET',
			};
			httpRequest(options, function(err, httpresponse) {
				/*if(err) {
					var data = {
						error: err.toString()
					}
				} else {*/
					var data = {
						error: false,
						response: {
							hostname: req.body.hostname,
							port: req.body.port,
							TLSHandshake: pqcresult,
							HTTPResponse: httpresponse
						}
					}
				//}
				res.json(data);
			});
		}
	});
});

function testPostQuantum(options, callback) {
	var netcertoptions = {
		hostname: options.hostname,
		port: options.port,
		//starttls: false,
		protocol: 'https'
	}
	netcertoptions.groups = [
		"x25519_kyber768",
		"x25519_kyber512",
		"p256_kyber768"
	]
	/*netcertoptions.groups = [
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
    ]
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
    ];*/
	openssl2.x509.TLSHandshake(netcertoptions, function(err, pqc, cmd) {
		let pqcready = true;
		if(err) {
			pqcready = false;
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
			]
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
			openssl2.x509.TLSHandshake(netcertoptions, function(err, notpqc, cmd) {
				if(err) {
					callback(err.toString(), false);
				} else {
					let pc = new parseCerts();
					pc.parse(notpqc.data.certs, function(err, certs) {
						//console.log(certs);
						callback(false, {
							pqcready: pqcready,
							data: notpqc,
							parsedCerts: certs, 
							cmd: cmd
						});
					});
				}
			});
		} else {
			let pc = new parseCerts();
			pc.parse(pqc.data.certs, function(err, certs) {
				//console.log(certs);
				callback(false, {
					pqcready: pqcready,
					data: pqc,
					parsedCerts: certs, 
					cmd: cmd
				});
			});
		}
	});
}

function parseCerts() {
	var pc = []
	var i = 0;
	var certs = [];

	this.parse = function(c, callback) {
		certs = c;
		parse(callback)
	}

	parse = function(callback) {
		openssl2.x509.parse({cert: certs[i]}, function(err, parsed) {
			if(err) {
				//console.log(i);
			} else {
				let name;
				if(parsed.data.subject.commonName) {
					if(typeof parsed.data.subject.commonName == 'string') {
						name = parsed.data.subject.commonName;
					} else {
						name = parsed.data.subject.commonName[0];
					}
				} else {
					name = 'Certificate ' + i;
				}
				pc.push ({
					name: name,
					cert: certs[i]
				});
			}
			i++;
			if(i < certs.length) {
				parse(callback);
			} else {
				callback(false, pc);
			}
		});
	}
}

var httpRequest2 = function(params, callback) {
    //console.log(params);
    const req = https.request(params.options, res => {
        var resp = [];

        res.on('data', function(data) {
			//console.log(data);
            resp.push(data);
        });

        res.on('end', function() {
            callback(false, {statusCode: res.statusCode, options: params.options, headers: res.headers, body: Buffer.concat(resp).toString()});
        });
    })

    req.on('error', function(err) {
        console.log(err.toString());
        callback(false, {statusCode: false, options: params.options, headers: false, body: JSON.stringify({ error: err.toString()})});
    })

    if(params.options.method=='POST') {
        req.write(JSON.stringify(params.body));
    }

    req.end()
}

function httpRequest(options, callback) {
	const req = https.request(options, (res) => {
		//console.log('statusCode:', res.statusCode);
		//console.log('headers:', res.headers);
		let resp = [];
		
		res.on('data', (d) => {
			//process.stdout.write(d);
			resp.push(d);
		});

		res.on('end', () => {
			callback(false, {
				statusCode: res.statusCode,
				headers: res.headers,
				responseBody: Buffer.concat(resp).toString()
			});
		});
	});
	  
	req.on('error', (e) => {
		//console.error(e);
		callback(e, false);
	});

	req.end(); 
}

router.post('/generateECCPrivateKey', function(req, res) {
	sendRequestToOS('key', req, function(err, result){});
	var rsakeyoptions = req.body;
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.generateECCPrivateKey(rsakeyoptions, function(err, key, cmd) {
		if(err) {
			var data = {
				error: err,
				key: key,
				command: cmd
			}
		} else {
			var data = {
				error: false,
				key: key,
				command: cmd
			}
		}
		res.json(data);
	});
});

var usageData = function(data) {
	//console.log(data);
	if(email.emailParams) {
		let transporter = nodemailer.createTransport(
			email.nodemailertransportparams
		);
		
		let mailOptions = email.nodemailermailoptions
		
		//console.log(JSON.stringify(data));
		//mailOptions.html = JSON.stringify(data, null, 4);
		mailOptions.text = JSON.stringify(data, null, 4);
		
		transporter.sendMail(mailOptions, (error, info) => {
			if (error) {
				return console.log(error);
			}
			//console.log('Message sent: %s', info.messageId);
			// Preview only available when sending through an Ethereal account
			//console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

			// Message sent: <b658f8ca-6296-ccf4-8306-87d57a0b4321@example.com>
			// Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
		});
	}
}

router.post('/generateCSR', function(req, res) {
	sendRequestToOS('x509', req, function(err, result){});
	var key = req.body.key;
	var keypass = req.body.keypass;
	var csroptions = req.body.options;
	var sign = req.body.sign;
	//console.log(JSON.stringify(csroptions, null, 4));
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.generateCSR(csroptions, key, keypass, function(err, csr, cmd) {
		if(sign=='nosign') {
			let usagedata = {
				action: 'CSROnly',
				err: err,
				headers: req.headers,
				csroptions: csroptions,
				csr: csr
			}
			usageData(usagedata);
		} else if(sign=='simplecsr') {
			let usagedata = {
				action: 'simpleCSR',
				err: err,
				headers: req.headers,
				csroptions: csroptions,
				csr: csr
			}
			usageData(usagedata);
		}
		if(err) {
			var data = {
				error: err,
				csr: csr,
				command: cmd
			}
		} else {
			var data = {
				error: false,
				csr: csr,
				command: cmd
			}
		}
		res.json(data);
	});
});

router.post('/selfSignCSR', function(req, res) {
	sendRequestToOS('x509', req, function(err, result){});
	var key = req.body.key;
	var keypass = req.body.keypass;
	var csroptions = req.body.options;
	var csr = req.body.csr;
	//console.log(req.body);
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.selfSignCSR(csr, csroptions, key, keypass, function(err, crt, cmd) {
		let usagedata = {
			action: 'SelfSign',
			err: err,
			headers: req.headers,
			csroptions: csroptions,
			csr: csr,
			crt: crt
		}
		usageData(usagedata);
		if(err) {
			var data = {
				error: err,
				crt: crt,
				command: cmd
			}
		} else {
			var data = {
				error: false,
				crt: crt,
				command: cmd
			}
		}
		res.json(data);
	});
});

router.post('/CASignCSR', function(req, res) {
	sendRequestToOS('x509', req, function(err, result){});
	var keypass = req.body.keypass;
	var csroptions = req.body.options;
	let cadir = getCADir(req);
	if(req.body.ca.path) {
		if(config.publichttp) {
			//console.log(csroptions);
			let hash = '';
			if(config.caIPDir) {
				let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
				hash = md5(ip) + '/';
			}
			if(csroptions.extensions) {
                                //already exists
                        } else {
				csroptions.extensions = {};
                        }
			csroptions.extensions.authorityInfoAccess = {};
			csroptions.extensions.authorityInfoAccess.caIssuers = ['http://' + config.publichttp.replace('http://', '') + '/public/issuer/' + hash + req.body.ca.path.replace(/ /g, "_") + '.crt'];
			csroptions.extensions.authorityInfoAccess.OCSP = ['http://' + config.publichttp.replace('http://', '') + '/public/ocsp/' + hash + req.body.ca.path.replace(/ /g, "_")];
			csroptions.extensions.crlDistributionPoints = ['http://' + config.publichttp.replace('http://', '') + '/public/crl/' + hash + req.body.ca.path.replace(/ /g, "_") + '.crl'];
		}
		fs.readFile(cadir + '/' + req.body.ca.path + '/ca.key', function(err, key) {
			//console.log(data);
			fs.readFile(cadir + '/' + req.body.ca.path + '/ca.crt', function(err, cacrt) {
				fs.stat(cadir + '/' + req.body.ca.path + '/ca.chain', function(err, stat) {
					if(err == null) {
						fs.readFile(cadir + '/' + req.body.ca.path + '/ca.chain', function (err, chain) {
							var capath = cadir + '/' + req.body.ca.path;
							//var serialpath = process.cwd() + serial.substr(1, serial.length);
							openssl.CASignCSR(req.body.csr, req.body.options, capath, cacrt.toString(), key.toString(), req.body.ca.keypass, function(err, crt, cmd) {
								let usagedata = {
									action: 'CASign',
									err: err,
									headers: req.headers,
									csroptions: req.body.options,
									csr: req.body.csr,
									crt: crt,
									cacrt: cacrt.toString() + chain.toString()
								}
								usageData(usagedata);
								fs.writeFile(cadir + '/' + req.body.ca.path + '/config.txt', cmd.files.config, function(err) {
								
								});
								if(err) {
									var data = {
										error: err,
										cacrt: cacrt.toString() + chain.toString(),
										crt: crt,
										command: cmd
									}
								} else {
									var data = {
										error: false,
										cacrt: cacrt.toString() + chain.toString(),
										crt: crt,
										command: cmd
									}
								}
								res.json(data);
								//return;
							});
						})
					} else if(err.code == 'ENOENT') {
						// file does not exist
						//console.log('does not exist');
						var capath = cadir + '/' + req.body.ca.path;
						//var serialpath = process.cwd() + serial.substr(1, serial.length);
						openssl.CASignCSR(req.body.csr, req.body.options, capath, cacrt.toString(), key.toString(), req.body.ca.keypass, function(err, crt, cmd) {
							let usagedata = {
								action: 'CASign',
								err: err,
								headers: req.headers,
								csroptions: req.body.options,
								csr: req.body.csr,
								crt: crt,
								cacrt: cacrt.toString()
							}
							usageData(usagedata);
							fs.writeFile(cadir + '/' + req.body.ca.path + '/config.txt', cmd.files.config, function(err) {
								
							});
							if(err) {
								var data = {
									error: err,
									cacrt: cacrt.toString(),
									crt: crt,
									command: cmd
								}
							} else {
								var data = {
									error: false,
									cacrt: cacrt.toString(),
									crt: crt,
									command: cmd
								}
							}
							res.json(data);
							//return;
						});
					} else {
						//console.log('Some other error: ', err.code);
					}
					//console.log(data);
				});
			});
		});
	} else {
		var key = req.body.key;
		var csr = req.body.csr;
		//console.log(req.body);
		//res.json(req.body);
		//return;
		//var username = req.body.username;
		//var password = req.body.password;
		openssl.CASignCSR(req.body.csr, req.body.options, false, req.body.ca.cert, req.body.ca.key, req.body.ca.keypass, function(err, crt, cmd) {
			let usagedata = {
				action: 'CASign',
				err: err,
				headers: req.headers,
				csroptions: req.body.options,
				csr: req.body.csr,
				crt: crt,
				cacrt: req.body.ca.cert
			}
			usageData(usagedata);
			if(err) {
				var data = {
					error: err,
					crt: crt,
					command: cmd
				}
			} else {
				var data = {
					error: false,
					crt: crt,
					command: cmd
				}
			}
			res.json(data);
		});
	}
});

router.post('/pasteKey', function(req, res) {
	//console.log(req.body);
	var key = req.body.key;
	var password = req.body.password;
	openssl.importRSAPrivateKey(key, password, function(err, key, cmd) {
		if(err) {
			var data = {
				error: err,
				key: key,
				command: cmd
			}
		} else {
			var data = {
				error: false,
				key: key,
				command: cmd
			}
		}
		res.json(data);
	});
});

router.post('/ocspChecker', function(req, res) {
	sendRequestToOS('ocsp', req, function(err, result){});
	var ocsp = new ocsplib();
	console.log(req.body)
	if(req.body.method=='download') {
		console.log('OCSP download for: ' + req.body.hostname + ':' + req.body.port);
	} else if(req.body.method=='paste') {
		console.log('OCSP pasted cert:');
		console.log(req.body.cert);
	} else {
		console.log('OCSP unrecognized method!');
	}
	var netcertoptions = {
		        hostname: req.body.hostname,
		        port: req.body.port,
		        starttls: false,
		        protocol: 'https'
	}
	//console.log(netcertoptions);
	if(req.body.method=='download') {
		ocsp.getCertFromNetwork(netcertoptions, function(err, response, cmd) {
			var data = {
				error: err,
				response: response,
				command: cmd
			}
			//console.log(cmd.cert);
			//console.log(err);
			//console.log(response);
			if(err || response.indexOf('unauthorized') >= 0) {
				if(cmd.cert) {
					ocsp.query(cmd.cert.base64, function(err, response, cmd) {
						let usagedata = {
								action: 'OCSPBadChainDownload',
								err: err,
								headers: req.headers,
								ocsp: response
						}
						usageData(usagedata);
						data = {
							error: err,
							response: response,
							command: cmd
						}
						if(err) {
							res.json(data);
						} else {
							res.json(data);
						}
					});
				} else {
					res.json({error: err});
				}
			} else {
				let usagedata = {
										action: 'OCSPDownload',
										err: err,
										headers: req.headers,
										ocsp: response
									}
				usageData(usagedata);
				res.json(data);
			}
		});
	} else {
		ocsp.query(req.body.cert, function(err, response, cmd) {
			let usagedata = {
                                action: 'OCSPPaste',
                                err: err,
                                headers: req.headers,
                                ocsp: response
                        }
                        usageData(usagedata);
			data = {
				error: err,
				response: response,
				command: cmd
			}
			if(err) {
				//console.log(data);
				res.json(data);
			 } else {
				//console.log(resp);
				//for(var i = 0; i <= cmd.ca.length - 1; i++) {
				//      console.log(cmd.ca[i]);
				//}
				//console.log(cmd.cert);
				//console.log(data);
				res.json(data);
			}
		});
	}
});

router.post('/pasteECCKey', function(req, res) {
	//console.log(req.body);
	var key = req.body.key;
	var password = req.body.password;
	openssl.importECCPrivateKey(key, password, function(err, key, cmd) {
		if(err) {
			var data = {
				error: err,
				key: key,
				command: cmd
			}
		} else {
			var data = {
				error: false,
				key: key,
				command: cmd
			}
		}
		res.json(data);
	});
});

var createCADir = function(cadir, param) {
	try {
		if(fs.statSync(cadir + '/' + param.name)) {
			//console.log('CA Name Exists.');
			return true;
		}
		//fs.mkdirSync(cadir + '/' + param.name);
	} catch(e) {
		//this should happen because the file shouldn't exist
		//console.log(e);
		//return true;
	}
	fs.mkdirSync(cadir + '/' + param.name);
	fs.writeFile(cadir + '/' + param.name + '/ca.key', param.key, function(err) {
		if(err) {
			return true;
		} else {
			fs.writeFile(cadir + '/' + param.name + '/ca.crt', param.cert, function(err) {
				if(err) {
					return true;
				} else {
					fs.writeFile(cadir + '/' + param.name + '/index.txt', '', function(err) {
						if(err) {
							return true;
						} else {
							fs.writeFile(cadir + '/' + param.name + '/index.txt.attr', '', function(err) {
								if(err) {
									return true;
								} else {
									if(param.keypass) {
										fs.writeFileSync(cadir + '/' + param.name + '/capass.txt', param.keypass);
									}
									if(param.chain) {
										fs.writeFileSync(cadir + '/' + param.name + '/ca.chain', param.chain);
									}
								}
								fs.mkdirSync(cadir + '/' + param.name + '/certs');
							});
						}
					});
				}
			});
		}
	});
}

router.post('/saveCA', function(req, res) {
	//console.log(req.body);
	let cadir = getCADir(req);
	var name = req.body.name;
	var key = req.body.key;
	var cert = req.body.cert;
	var chain = req.body.chain;
	var response = {
		error: false,
		data: req.body
	}
	fs.stat(cadir, function(err, stat) {
		if(err == null) {
			response.error = createCADir(cadir, req.body);
			res.json(response);
		} else if(err.code == 'ENOENT') {
			fs.mkdirSync(cadir);
			response.error = createCADir(cadir, req.body);
			res.json(response);
		} else {
			//console.log('Some other error: ', err.code);
			//res.json(false);
		}
	});
});

module.exports = router
