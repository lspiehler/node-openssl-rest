var express = require('express'),
router = express.Router();
var openssl = require('../lib/openssl.js');
var ocspcache = require('../lib/ocspcache.js');
var multer  = require('multer')
var upload = multer();
const http = require('http');
var fs = require('fs');
var config = require('../config.js');
const { spawn } = require( 'child_process' );
const opensslbinpath = config.opensslbinpath; //use full path if not in system PATH
var tmp = require('tmp');
var moment = require('moment');
var md5 = require('md5');
var Ber = require('asn1').Ber;

/*var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}*/

var getCADir = function(req) {
	let cadir;
	
	let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
	console.log('HTTP connection from ' + ip);
	
	//console.log(req.headers);
	if(config.caIPDir) {
		cadir = './ca/' + ip.replace(/:/g,'-');
		return cadir;
	} else {
		cadir = './ca/global';
		return cadir;
	}
}

var routeIssuer = function(req, res, global) {
	let cadir;
	if(global) {
		cadir = './ca/global';
	} else {
		cadir = './ca/' + req.params.dir;
	}
	let caname = req.params.ca.replace(/_/g, " ").replace('.crt' , '');
	fs.stat(cadir + '/' + caname + '/ca.der', function(err, stat) {
		if(err == null) {
			console.log('Issuer lookup for ' + caname + ', DER exists');
			fs.readFile(cadir + '/' + caname + '/ca.der', function(err, der) {
				var mimetype = 'application/x-x509-ca-cert';
				res.setHeader('Content-disposition', 'attachment; filename=' + caname + '.cer');
				res.setHeader('Content-type', mimetype);
				res.charset = 'UTF-8';
				//console.log(command);
				res.send(der);
			});
		} else if(err.code == 'ENOENT') {
			fs.stat(cadir + '/' + caname + '/ca.crt', function(err, stat) {
				if(err == null) {
					console.log('Issuer lookup for ' + caname + ', creating DER');
					//console.log('here');
					fs.readFile(cadir + '/' + caname + '/ca.crt', function(err, data) {
						openssl.convertPEMtoDER(data.toString(), function(err, der, cmd){
							fs.writeFile(cadir + '/' + caname + '/ca.der', der, function(err) {
								var mimetype = 'application/x-x509-ca-cert';
								res.setHeader('Content-disposition', 'attachment; filename=' + caname + '.cer');
								res.setHeader('Content-type', mimetype);
								res.charset = 'UTF-8';
								//console.log(command);
								res.send(der);
							});
						});
					});
				} else {
					//console.log('here');
					console.log('Issuer lookup for ' + caname + ' does not exist');
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
}

router.get('/issuer/:ca', function(req, res) {
	routeIssuer(req, res, true);
});

router.get('/issuer/:dir/:ca', function(req, res) {
	routeIssuer(req, res, false);
});

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

var genCRL = function(capath, callback) {
	fs.readFile(capath + '/config.txt', function(err, caconfig) {
		if (err) callback(err, false);
		//console.log(caconfig.toString());
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, caconfig, function() {
				fileExists(capath + '/capass.txt', function(err, stat) {
					let command;
					if (err) {
						command = 'ca -config ' + path + ' -gencrl -passin pass:';
					} else {
						command = 'ca -config ' + path + ' -gencrl -passin file:capass.txt';
					}
					runOpenSSLCommand(command, capath, function(err, out) {
						if(err) {
							//console.log(err);
							callback(err, out);
						} else {
							fs.writeFile(capath + '/ca.crl', out.stdout, function(err) {
								callback(false, out);
							});
						}
						cleanupCallback();
					});
				});
			});
		});
	});
}

var sendCRL = function(err, name, crl, res, callback) {
	if(err) {
		console.log(err);
		res.status(404);
		res.send('Unable to create or find CRL.');
	} else {
		var mimetype = 'application/pkix-crl';
		res.setHeader('Content-disposition', 'attachment; filename=' + name + '.crl');
		res.setHeader('Content-type', mimetype);
		res.charset = 'UTF-8';
		res.send(crl);
	}
}

var routeCRL = function(req, res, global) {
	let cadir;
	if(global) {
		cadir = './ca/global';
	} else {
		cadir = './ca/' + req.params.dir;
	}
	//console.log(cadir);
	let caname = req.params.ca.replace(/_/g, " ").replace('.crl' , '');
	fileExists(cadir + '/' + caname + '/ca.crl', function(err, stat) {
		if(stat) {
			//console.log(stat);
			let now = moment();
			//console.log(now);
			let crldate = moment(stat.mtime);
			//console.log(crldate.diff(now, 'hours'));
			let crlage = now.diff(crldate, 'hours');
			if(crlage < 23) {
				console.log('CRL for ' + caname + ' exists and is only ' + crlage + ' hours old.');
				fs.readFile(cadir + '/' + caname + '/ca.crl', function(err, crl) {
					sendCRL(err, caname, crl, res, function() {
						//respond to request for CRL
					});
				});
			} else {
				console.log('CRL for ' + caname + ' exists, but will be regenerated because it is ' + crlage + ' hours old.');
				genCRL(cadir + '/' + caname, function(err, out) {
					//console.log(out);
					sendCRL(err, caname, out.stdout, res, function() {
						//respond to request for CRL
					});
				});
			}
		} else {
			fileExists(cadir + '/' + caname + '/ca.crt', function(err, stat) {
				if(stat) {
					console.log('CRL for ' + caname + ' does not exist and will be generated.');
					genCRL(cadir + '/' + caname, function(err, out) {
						//console.log(out);
						sendCRL(err, caname, out.stdout, res, function() {
							//respond to request for CRL
						});
					});
				} else {
					console.log('attempted CRL lookup for non-existent CA: ' + caname);
					res.status(404);
					res.send('Unable to create or find CRL.');
				}
			});
		}
	});
}

router.get('/crl/:ca', function(req, res) {
	routeCRL(req, res, true);
});

router.get('/crl/:dir/:ca', function(req, res) {
	routeCRL(req, res, false);
});

var generateOCSPCert = function(capath, callback) {
	var rsakeyoptions = {
		rsa_keygen_bits: 2048,
		format: 'PKCS8'
	}
	
	var csroptions = {
		hash: 'sha512',
		days: 7,
		subject: {
			commonName: [
				'OCSP'
			],
			emailAddress: 'admin@emil.md'
		},
		extensions: {
			basicConstraints: {
				critical: true,
				CA: false
			},
			keyUsage: {
				critical: true,
				usages: [
					'digitalSignature'
				]
			},
			extendedKeyUsage: {
				critical: true,
				usages: [
					'OCSPSigning'
				]	
			}
		}
	}
	
	openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
		openssl.generateCSR(csroptions, key, false, function(err, csr, cmd) {
			//fs.readFile(capath + '/config.txt', function(err, caconfig) {
				//if (err) callback(err, false);
				//tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
				//if (err) throw err;
					//fs.writeFile(path, caconfig, function() {
						fs.readFile(capath + '/capass.txt', function(err, capass) {
							let pass;
							if(err) {
								pass = false;
							} else {
								pass = capass.toString();
							}
							openssl.CASignCSR(csr, csroptions, capath, false, false, pass, function(err, crt, cmd) {
								if(err) {
									callback(true);
									console.log(err);
									//console.log(cmd);
								} else {
									//console.log(crt);
									//console.log(cmd);
									fs.writeFile(capath + '/ocsp.key', key, function() {
										fs.writeFile(capath + '/ocsp.crt', crt, function() {
											callback(false);
										});
									});
								}
							});
						});
					//});
				//});
			
		});
	});
}

var startOCSPServer = function(cadir, port, attempts, alt, callback) {
	//const stdoutbuff = [];
	const stderrbuff = [];
	var nevermind = false;
	
	let cmd = [];
	
	if(alt) {
		cmd.push('ocsp -port 127.0.0.1:' + port + ' -sha256 -index index.txt -CA ca.crt -rkey ocsp.key -rsigner ocsp.crt -ndays 1');
	} else {
		cmd.push('ocsp -port ' + port + ' -rmd sha256 -index index.txt -CA ca.crt -rkey ocsp.key -rsigner ocsp.crt -ndays 1');
	}
	
	try {
		var stat = fs.statSync(cadir + '/ca.chain');
		if(stat) {
			cmd.push('-CAfile ca.chain');
		}
	} catch(e) {
		//this must be a root ca. No chain exists
	}
	
	//if(config.caIPDir) {
		cmd.push('-nrequest 1');
	//}
	
	//console.log(cmd.join(''));
	
	var openssl = spawn( opensslbinpath, cmd.join(' ').split(' '), {cwd: cadir} );
	
	var hack = setTimeout(function() {
		console.log('got called');
		nevermind = true;
		callback(false, openssl, port);
		return;
	}, 2000);
	
	openssl.stdout.on('data', function(data) {
		console.log(data.toString());
		//console.log('here');
		//stdoutbuff.push(data.toString());
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
		if(nevermind) {
			
		} else {
			//console.log(data.toString());
			//console.log('here');
			if(hack) {
				clearTimeout(hack);
			}
			if(data.toString().indexOf('Waiting for OCSP client connections...') >= 0) {
				//console.log('STARTED');
				//console.log(data.toString().replace('\n',''));
				callback(false, openssl, port);
				return;
			} else if(data.toString().indexOf('ocsp: Can\'t parse "127.0.0.1:30000" as a number') >= 0) {
				startOCSPServer(cadir, port + nextport, attempts - 1, true, callback);
			} else {
				stderrbuff.push(data.toString());
				//console.log(data.toString());
			}
		}
	});
	
	/*openssl.on('SIGINT', function() {
		openssl.kill();
	});
	
	openssl.on('SIGTERM', function() {
		openssl.kill();
	});*/
	
	openssl.on('exit', function(code) {
		if(hack) {
			clearTimeout(hack);
		}
		var out = {
			command: 'openssl ' + cmd,
			//stdout: stdoutbuff.join(''),
			//stderr: stderrbuff.join(''),
			exitcode: code
		}
		console.log('OCSP responder exiting: ' + code);
		if (code != 0) {
			console.log('non zero exit');
			if(stderrbuff.join('').indexOf('Address already in use') >= 0) {
				console.log('address already in use');
				if(attempts <= 1) {
					callback('ERROR: ' + stderrbuff.join(''), openssl, port);
					return;
				} else {
					let nextport = Math.floor((Math.random() * 100) + 1);
					startOCSPServer(cadir, port + nextport, attempts - 1, alt, callback);
				}
			} else {
				console.log('non zero exit and not address already in use');
				callback('ERROR: ' + stderrbuff.join(''), openssl, port);
				return;
			}
		} else {
			console.log('zero exit status');
			callback(false, openssl, port);
			return;
		}
		//openssl = null;
	});
}

var OCSPProcessManager = function() {
	var startport = 30000;
	var processes = {};
	var ports = [];
	
	var OCSPProcess = function(process, cadir, port) {
		this.process = process;
		this.cadir = cadir;
		this.port = port;
	}
	
	var exists = function(hash) {
		if(processes[hash]) {
			return processes[hash];
		} else {
			return false;
		}
	}
	
	this.exists = function(hash) {
		//console.log(processes);
		return exists(hash);
	}
	
	this.start = function(hash, cadir, callback) {
		startOCSPServer(cadir, startport, 5, false, function(err, process, port) {
			let ocsp = new OCSPProcess(
				process,
				cadir,
				port
			);
			//console.log(ocsp.process.exitCode);
			processes[hash] = ocsp;
			if(err) {
				console.log('ERROR: OCSP process non-zero exit status on port: ' + port);
				callback(err, ocsp);
			} else {
				if(process.exitCode==null) {
					console.log('Started OCSP process on port: ' + port);
					callback(false, ocsp);
					if(port > 40000) {
						startport = 30000;
					} else {
						startport = port + 1;
					}
				} else {
					console.log('Ended OCSP process on port: ' + port);
				}
			}
		});
	}
}

var proxyOCSP = function(req, port, data, callback) {
	var options = {
		hostname: '127.0.0.1',
		port: port,
		path: '/',
		method: 'POST',
		headers: {
			'Content-Type': 'application/ocsp-request',
			'Content-Length': req.headers['content-length']
		}
	};
	
	var ocspreq = http.request(options, (ocspres) => {
		var ocspresponse = [];
		
		//console.log('statusCode:', ocspres.statusCode);
		//console.log('headers:', ocspres.headers);

		ocspres.on('data', (d) => {
			ocspresponse.push(d);
		});
		
		ocspres.on('end', () => {
			//console.log(ocspresponse.toString());
			//res.send(Buffer.concat(ocspresponse));
			callback(false, Buffer.concat(ocspresponse));
			return;
		});
	});

	ocspreq.on('error', (e) => {
		//console.error(e);
		callback(e, false);
		return
	});

	ocspreq.write(data);
	ocspreq.end();
	
	//console.log(data);
	//res.status(404);
	//res.send('error');
}

var queryOCSP = function(req, res, cadir, callback) {
	var data = [];
	req.on('data', function(chunk) {
		data.push(chunk);
	});
	
	req.on('end', function() {
		var request = Buffer.concat(data);
		//console.log(req.headers);
		//console.log(request.toString('hex'));
		var reader = new Ber.Reader(request);
		var oid;
		while(oid != 6) {
			reader.readSequence();
			oid = reader.peek();
		}
		reader.readOID();
		reader.readByte();
		reader.readByte();
		let issuernamehash = reader.readString(Ber.OctetString, true).toString('hex');
		let issuerkeyhash = reader.readString(Ber.OctetString, true).toString('hex');
		let serialnumber = reader.readString(Ber.Integer, true).toString('hex');
		let issuerhash = md5(issuernamehash + issuerkeyhash);
		console.log(issuerhash);
		console.log('issuerNameHash: ' + issuernamehash);
		console.log('issuerKeyHash: ' + issuerkeyhash);
		console.log('serialNumber: ' + serialnumber);
		let cache = ocspcache.getRequest(issuerhash, serialnumber);
		if(cache) {
			console.log('ocsp cache hit');
			//console.log(cache);
			res.send(cache.response);
			callback(false);
		} else {
			console.log('ocsp cache miss');
			let hash = md5(cadir);
			let process = OCSPManager.exists(hash);
			if(process) {
				//console.log(process.process);
				if(process.process.exitCode==null) {
					console.log('OCSP process container exists and appears to be alive');
					proxyOCSP(req, process.port, request, function(err, response) {
						if(err) {
							//if it fails, restart the OCSP service and try one more time
							console.log('OCSP process did not respond. Restarting process and trying one more time.');
							OCSPManager.start(hash, cadir, function(err, process) {
								if(err) {
									console.log('OCSP process failed to start. Not trying again');
									console.log(err);
									callback(true);
								} else {
									proxyOCSP(req, process.port, request, function(err, response) {
										if(err) {
											console.log('OCSP process failed to respond after the second attempt');
											console.log(err);
											callback(true);
										} else {
											ocspcache.addResponse(issuerhash, serialnumber, response);
											res.send(response);
											callback(false);
										}
									});
								}
							});
						} else {
							ocspcache.addResponse(issuerhash, serialnumber, response);
							res.send(response);
							callback(false);
						}
					});
				} else {
					console.log('OCSP process container exists, but process is dead');
					OCSPManager.start(hash, cadir, function(err, process) {
						if(err) {
							console.log(err);
						} else {
							proxyOCSP(req, process.port, request, function(err, response) {
								if(err) {
									console.log(err);
									callback(true);
								} else {
									ocspcache.addResponse(issuerhash, serialnumber, response);
									res.send(response);
									callback(false);
								}
							});
						}
					});
				}
			} else {
				console.log('No existing OCSP process');
				OCSPManager.start(hash, cadir, function(err, process) {
					if(err) {
						console.log(err);
					} else {
						proxyOCSP(req, process.port, request, function(err, response) {
							if(err) {
								console.log(err);
								callback(true);
							} else {
								ocspcache.addResponse(issuerhash, serialnumber, response);
								//console.log(response.toString());
								res.send(response);
								callback(false);
							}
						});
					}
				});
			}
		}
	});
	
	req.on('error', (e) => {
		//console.error(e);
		//callback(true);
		//return;
	});
}

var OCSPManager = new OCSPProcessManager();

var processOCSPRequest = function(req, res, cadir, callback) {
	queryOCSP(req, res, cadir, function(err) {
		if(err) {
			callback(false);
		} else {
			callback(false);
		}
	});
	/*return;
	//let hash = md5(cadir);
	//let process = OCSPManager.exists(hash);
	if(process) {
		//console.log(process.process);
		if(process.process.exitCode==null) {
			console.log('OCSP process container exists and appears to be alive');
			queryOCSP(req, res, cadir, function(err) {
				if(err) {
					console.log('OCSP process did not respond. Attempting to restart.');
					OCSPManager.start(hash, cadir, function(err, process) {
						if(err) {
							console.log(err);
						} else {
							queryOCSP(req, res, process.port, function(err) {
								if(err) {
									callback(true);
								} else {
									callback(false);
								}
							});
						}
					});
				} else {
					callback(false);
				}
			});
		} else {
			console.log('OCSP process container exists, but process is dead');
			OCSPManager.start(hash, cadir, function(err, process) {
				if(err) {
					console.log(err);
				} else {
					queryOCSP(req, res, process.port, function(err) {
						if(err) {
							callback(true);
						} else {
							callback(false);
						}
					});
				}
			});
		}
	} else {
		console.log('No existing OCSP process');
		OCSPManager.start(hash, cadir, function(err, process) {
			if(err) {
				console.log(err);
			} else {
				queryOCSP(req, res, process.port, function(err) {
					if(err) {
						callback(true);
					} else {
						callback(false);
					}
				});
			}
		});
	}*/
}

var routeOCSP = function(req, res, global) {
	let caname = req.params.ca.replace(/_/g, " ");
	let cadir;
	if(global) {
		cadir = './ca/global' + '/' + caname;;
	} else {
		cadir = './ca/' + req.params.dir + '/' + caname;;
	}
	//console.log(cadir);
	fileExists(cadir + '/ca.crt', function(err, stat) {
		if(stat) {
			fileExists(cadir + '/ocsp.crt', function(err, stat) {
				if(stat) {
					//console.log(stat);
					let now = moment();
					//console.log(now);
					let ocspcertdate = moment(stat.mtime);
					//console.log(ocspcertdate.diff(now, 'days'));
					let ocspcertage = now.diff(ocspcertdate, 'days');
					if(ocspcertage <= 7) {
						console.log('Existing OCSP certificate OK:' + ocspcertage + ' days old.');
						processOCSPRequest(req, res, cadir, function() {
								
						});
					} else {
						console.log('Existing OCSP certificate EXPIRED:' + ocspcertage + ' days old. Generating a new one...');
						generateOCSPCert(cadir, function(err) {
							processOCSPRequest(req, res, cadir, function() {
								
							});
						});
					}
				} else {
					console.log('Generating OCSP certificate...');
					generateOCSPCert(cadir, function(err) {
						processOCSPRequest(req, res, cadir, function() {
							
						});
					});
				}
			});
		} else {
			console.log('OCSP lookup for ' + caname + ' does not exist');
			res.status(404);
			res.send('CA does not exist');
		}
	})
}

router.post('/ocsp/:dir/:ca', function(req, res) {
	//console.log(req);
	routeOCSP(req, res, false);
});

router.post('/ocsp/:ca', function(req, res) {
	//console.log(req.body);
	routeOCSP(req, res, true);
});

module.exports = router
