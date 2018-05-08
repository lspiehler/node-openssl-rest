var express = require('express'),
router = express.Router();
var openssl = require('../lib/openssl.js');
var multer  = require('multer')
var upload = multer();
const http = require('http');
var fs = require('fs');
var config = require('../config.js');
const { spawn } = require( 'child_process' );
const opensslbinpath = 'openssl'; //use full path if not in system PATH
var tmp = require('tmp');
var moment = require('moment');
var md5 = require('md5');

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

router.get('/issuer/:ca', function(req, res) {
	let cadir = getCADir(req);
	let caname = req.params.ca.replace(/_/g, " ").replace('.crt' , '');
	fs.stat(cadir + '/' + caname + '/ca.der', function(err, stat) {
		if(err == null) {
			console.log('Issuer lookup for ' + caname + ', DER exists');
			fs.readFile(cadir + '/' + caname + '/ca.crt', function(err, der) {
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
						openssl.convertPEMtoDER(data, function(err, der, cmd){
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
});

var fileExists = function(path, callback) {
	fs.stat(path, function(err, stat) {
		if(err == null) {
			callback(false, stat);
		} else if(err.code == 'ENOENT') {
			callback(false, false);
		} else {
			callback(err, false);
		}
	});
}

var runOpenSSLCommand = function(cmd, callback) {
	const stdoutbuff = [];
	const stderrbuff = [];
	
	const openssl = spawn( opensslbinpath, cmd.split(' ') );
	
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
				fs.readFile(capath + '/capass.txt', function(err, capass) {
					if (err) callback(err, false);
					let command = 'ca -config ' + path + ' -gencrl -passin pass:' + capass;
					runOpenSSLCommand(command, function(err, out) {
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

router.get('/crl/:ca', function(req, res) {
	//console.log('crl request');
	let caname = req.params.ca.replace(/_/g, " ").replace('.crl' , '');
	let cadir = getCADir(req);
	fileExists(cadir + '/' + caname + '/ca.crl', function(err, stat) {
		if(stat) {
			//console.log(stat);
			let now = moment();
			//console.log(now);
			let crldate = moment(stat.mtime);
			//console.log(crldate.diff(now, 'hours'));
			let crlage = now.diff(crldate, 'hours');
			if(crlage < 24) {
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
});

var generateOCSPCert = function(capath, callback) {
	var rsakeyoptions = {
		rsa_keygen_bits: 2048,
		format: 'PKCS8'
	}
	
	var csroptions = {
		hash: 'sha512',
		days: 2,
		subject: {
			commonName: [
				'OCSP'
			],
			emailAddress: 'lyas.spiehler@slidellmemorial.org'
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
		openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
			//fs.readFile(capath + '/config.txt', function(err, caconfig) {
				//if (err) callback(err, false);
				//tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
				//if (err) throw err;
					//fs.writeFile(path, caconfig, function() {
						fs.readFile(capath + '/capass.txt', function(err, capass) {
							openssl.CASignCSR(csr, csroptions, capath, false, false, capass, function(err, crt, cmd) {
								if(err) {
									callback(true);
									//console.log(err);
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
	
	if(config.caIPDir) {
		cmd.push('-nrequest 1');
	}
	
	var openssl = spawn( opensslbinpath, cmd.join(' ').split(' '), {cwd: cadir} );
	
	var hack = setTimeout(function() {
		callback(false, openssl, port);
		return;
	}, 2000);
	
	openssl.stdout.on('data', function(data) {
		console.log(data.toString());
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
		console.log(data.toString());
		if(hack) {
			clearTimeout(false, openssl, port);
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

	ocspreq.write(Buffer.concat(data));
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
		
		let hash = md5(cadir);
		let process = OCSPManager.exists(hash);
		if(process) {
			//console.log(process.process);
			if(process.process.exitCode==null) {
				console.log('OCSP process container exists and appears to be alive');
				proxyOCSP(req, process.port, data, function(err, response) {
					if(err) {
						//if it fails, restart the OCSP service and try one more time
						console.log('OCSP process did not respond. Restarting process and trying one more time.');
						OCSPManager.start(hash, cadir, function(err, process) {
							if(err) {
								console.log('OCSP process failed to start. Not trying again');
								console.log(err);
								callback(true);
							} else {
								proxyOCSP(req, process.port, data, function(err, response) {
									if(err) {
										console.log('OCSP process failed to respond after the second attempt');
										console.log(err);
										callback(true);
									} else {
										res.send(response);
										callback(false);
									}
								});
							}
						});
					} else {
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
						proxyOCSP(req, process.port, data, function(err, response) {
							if(err) {
								console.log(err);
								callback(true);
							} else {
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
					proxyOCSP(req, process.port, data, function(err, response) {
						if(err) {
							console.log(err);
							callback(true);
						} else {
							res.send(response);
							callback(false);
						}
					});
				}
			});
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

router.post('/ocsp/:ca', function(req, res) {
	let caname = req.params.ca.replace(/_/g, " ");
	let cadir = getCADir(req) + '/' + caname;
	fileExists(cadir + '/ocsp.crt', function(err, stat) {
		if(stat) {
			//console.log(stat);
			let now = moment();
			//console.log(now);
			let ocspcertdate = moment(stat.mtime);
			//console.log(ocspcertdate.diff(now, 'days'));
			let ocspcertage = now.diff(ocspcertdate, 'days');
			if(ocspcertage < 360) {
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
});

module.exports = router