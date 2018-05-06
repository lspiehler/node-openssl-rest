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
	//console.log(req.headers);
	if(config.caIPDir) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		cadir = './ca/' + ip.replace(/:/g,'-');
		return cadir;
	} else {
		cadir = './ca/global';
		return cadir;
	}
}

router.get('/issuer/:ca', function(req, res) {
	let cadir = getCADir(req);
	fs.stat(cadir + '/' + req.params.ca + '/ca.der', function(err, stat) {
		if(err == null) {
			console.log('Issuer lookup for ' + req.params.ca + ', DER exists');
			fs.readFile(cadir + '/' + req.params.ca + '/ca.crt', function(err, der) {
				var mimetype = 'application/x-x509-ca-cert';
				res.setHeader('Content-disposition', 'attachment; filename=' + req.params.ca + '.cer');
				res.setHeader('Content-type', mimetype);
				res.charset = 'UTF-8';
				//console.log(command);
				res.send(der);
			});
		} else if(err.code == 'ENOENT') {
			console.log('Issuer lookup for ' + req.params.ca + ', creating DER');
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
	let cadir = getCADir(req);
	fileExists(cadir + '/' + req.params.ca + '/ca.crl', function(err, stat) {
		if(stat) {
			//console.log(stat);
			let now = moment();
			//console.log(now);
			let crldate = moment(stat.mtime);
			//console.log(crldate.diff(now, 'hours'));
			let crlage = now.diff(crldate, 'hours');
			if(crlage < 24) {
				console.log('CRL for ' + req.params.ca + ' exists and is only ' + crlage + ' hours old.');
				fs.readFile(cadir + '/' + req.params.ca + '/ca.crl', function(err, crl) {
					sendCRL(err, req.params.ca, crl, res, function() {
						//respond to request for CRL
					});
				});
			} else {
				console.log('CRL for ' + req.params.ca + ' exists, but will be regenerated because it is ' + crlage + ' hours old.');
				genCRL(cadir + '/' + req.params.ca, function(err, out) {
					console.log(out);
					sendCRL(err, req.params.ca, out.stdout, res, function() {
						//respond to request for CRL
					});
				});
			}
		} else {
			console.log('CRL for ' + req.params.ca + ' does not exist and will be generated.');
			genCRL(cadir + '/' + req.params.ca, function(err, out) {
				console.log(out);
				sendCRL(err, req.params.ca, out.stdout, res, function() {
					//respond to request for CRL
				});
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
									console.log(crt);
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

var startOCSPServer = function(cadir, port, callback) {
	//const stdoutbuff = [];
	//const stderrbuff = [];
	
	let cmd = 'ocsp -resp_text -port 127.0.0.1:' + port + ' -sha256 -index index.txt -CAfile ca.chain -CA ca.crt -rkey ocsp.key -rsigner ocsp.crt -ndays 1';
	
	const openssl = spawn( opensslbinpath, cmd.split(' '), {cwd: cadir} );
	
	openssl.stdout.on('data', function(data) {
		//console.log(data.toString());
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
		if(data.toString().indexOf('Waiting for OCSP client connections...') >= 0) {
			console.log('STARTED');
			callback(false, openssl);
		}
	});
	
	openssl.on('SIGINT', function() {
		openssl.kill();
	});
	
	openssl.on('SIGTERM', function() {
		openssl.kill();
	});
	
	openssl.on('exit', function(code) {
		var out = {
			command: 'openssl ' + cmd,
			//stdout: stdoutbuff.join(''),
			//stderr: stderrbuff.join(''),
			exitcode: code
		}
		if (code != 0) {
			callback(true, openssl);
		} else {
			callback(false, openssl);
		}
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
		startport++;
		startOCSPServer(cadir, startport, function(err, process) {
			let ocsp = new OCSPProcess(
				process,
				cadir,
				startport
			);
			//console.log(ocsp.process.exitCode);
			processes[hash] = ocsp;
			if(err) {
				startport++;
				startOCSPServer(cadir, startport, function(err, process) {
					let ocsp = new OCSPProcess(
						process,
						cadir,
						startport
					);
					//console.log(ocsp.process.exitCode);
					processes[hash] = ocsp;
					if(err) {
						callback(err, ocsp);
					} else {
						callback(false, ocsp);
					}
				});
			} else {
				callback(false, ocsp);
			}
		});
	}
}

var queryOCSP = function(req, res, port, callback) {
	var data = [];
	req.on('data', function(chunk) {
		data.push(chunk);
	});
	req.on('end', function() {
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
			
			console.log('statusCode:', ocspres.statusCode);
			console.log('headers:', ocspres.headers);

			ocspres.on('data', (d) => {
				ocspresponse.push(d);
			});
			
			ocspres.on('end', () => {
				//console.log(ocspresponse.toString());
				res.send(Buffer.concat(ocspresponse));
				callback(false);
			});
		});

		ocspreq.on('error', (e) => {
			console.error(e);
			callback(true);
		});

		ocspreq.write(Buffer.concat(data));
		ocspreq.end();
		
		//console.log(data);
		//res.status(404);
		//res.send('error');
	});
	
	req.on('error', (e) => {
		console.error(e);
		callback(true);
	});
}

var OCSPManager = new OCSPProcessManager();

var processOCSPRequest = function(req, res, cadir, callback) {
	let hash = md5(cadir);
	let process = OCSPManager.exists(hash);
	if(process) {
		console.log(process);
		if(process.exitCode==null) {
			console.log('OCSP process exists and is alive');
			queryOCSP(req, res, process.port, function(err) {
				if(err) {
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
			console.log('OCSP rocess exists, but it is dead');
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
	}
}

router.post('/ocsp/:ca', function(req, res) {
	let cadir = getCADir(req) + '/' + req.params.ca;
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
