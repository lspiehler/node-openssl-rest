var express = require('express'), 
router = express.Router();
var openssl = require('../lib/openssl.js');
var multer  = require('multer')
var upload = multer();
var fs = require('fs');
var config = require('../config.js');
var email = require('../email.js');
const nodemailer = require('nodemailer');
var md5 = require('md5');
var ocsplib = require('../lib/ocsp_checker.js');

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
		cadir = './ca/' + md5(ip);
		return cadir;
	} else {
		cadir = './ca/global';
		return cadir;
	}
}

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
						CAs.push(file);
					}
					//if(file.isDirectory()) {	
						//splitfile.pop()
					//	CAs.push(file.join(''));
					//}
				});
				res.json(CAs);
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
	var command = [];
	//console.log(netcertoptions);
	openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
		//console.log(cmd);
		command.push(cmd);
		if(err) {
			var data = {
				error: err,
				csroptions: cert
			}
			res.json(data);
			return;
		} else {
			var certs = [];
			convertCertToCSR(certs, cert, 0, function(err, csroptions, cmd) {
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
	openssl.createPKCS7(certs, function(err, pkcs7, command) {
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
				} else {
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
				}
			}
		});
	});
	//var username = req.body.username;
	//var password = req.body.password;
});

router.post('/generateRSAPrivateKey', function(req, res) {
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

router.post('/generateECCPrivateKey', function(req, res) {
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
	var ocsp = new ocsplib();
	console.log(req.body)
	var netcertoptions = {
		        hostname: req.body.hostname,
		        port: 443,
		        starttls: false,
		        protocol: 'https'
	}

	ocsp.getCertFromNetwork(netcertoptions, function(err, response, cmd) {
		var data = {
			error: err,
			response: response,
			command: cmd
		}
		res.json(data);
	});
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
