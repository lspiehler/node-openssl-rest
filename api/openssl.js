var express = require('express'), 
router = express.Router();
var openssl = require('../lib/openssl.js');
var multer  = require('multer')
var upload = multer();
var fs = require('fs');
var config = require('../config.js');
const nodemailer = require('nodemailer');

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

router.get('/getCAs', function(req, res) {
	let CAs = [];
	let cadir = getCADir(req);
	console.log(cadir);
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
			openssl.convertCertToCSR(cert, function(err,csroptions,cmd) {
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
			});
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
		console.log(command);
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

router.post('/checkCAKey', function(req, res) {
	//console.log(req.file);
	let cadir = getCADir(req);
	if(req.body.password=='false' || req.body.password==false) {
		var password = false;
	} else {
		var password = req.body.password;
	}
	var capath = req.body.ca;
	fs.readFile(cadir + '/' + capath + '/' + capath + '.key', function(err, data) {
		//console.log(data);
		openssl.importRSAPrivateKey(data, password, function(err, key, cmd) {
			//console.log(key);
			if(err) {
				var data = false;
			} else {
				var data = {
					path: capath
				}
			}
			res.send(data);
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

var usageData = function(data) {
	console.log(data);
	if(config.emailParams) {
		let transporter = nodemailer.createTransport(
			config.nodemailertransportparams
		);
		
		let mailOptions = config.nodemailermailoptions
		
		//mailOptions.html = JSON.stringify(data, null, 4);
		mailOptions.text = JSON.stringify(data, null, 4);
		
		transporter.sendMail(mailOptions, (error, info) => {
			if (error) {
				return console.log(error);
			}
			console.log('Message sent: %s', info.messageId);
			// Preview only available when sending through an Ethereal account
			console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

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
	//console.log(csroptions);
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
		fs.readFile(cadir + '/' + req.body.ca.path + '/' + req.body.ca.path + '.key', function(err, key) {
			//console.log(data);
			fs.readFile(cadir + '/' + req.body.ca.path + '/' + req.body.ca.path + '.crt', function(err, cacrt) {
				fs.stat(cadir + '/' + req.body.ca.path + '/' + req.body.ca.path + '.chain', function(err, stat) {
					if(err == null) {
						fs.readFile(cadir + '/' + req.body.ca.path + '/' + req.body.ca.path + '.chain', function (err, chain) {
							var serial = cadir + '/' + req.body.ca.path + '/' + req.body.ca.path + '.srl';
							var serialpath = process.cwd() + serial.substr(1, serial.length);
							openssl.CASignCSR(req.body.csr, req.body.options, serialpath, cacrt.toString(), key.toString(), req.body.ca.keypass, function(err, crt, cmd) {
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
						var serial = cadir + '/' + req.body.ca.path + '/' + req.body.ca.path + '.srl';
						var serialpath = process.cwd() + serial.substr(1, serial.length);
						openssl.CASignCSR(req.body.csr, req.body.options, serialpath, cacrt.toString(), key.toString(), req.body.ca.keypass, function(err, crt, cmd) {
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

var createCADir = function(cadir, param) {
	try {
		if(fs.statSync(cadir + '/' + param.name)) {
			console.log('CA Name Exists.');
			return true;
		}
		//fs.mkdirSync(cadir + '/' + param.name);
	} catch(e) {
		//this should happen because the file shouldn't exist
		//console.log(e);
		//return true;
	}
	fs.mkdirSync(cadir + '/' + param.name);
	fs.writeFile(cadir + '/' + param.name + '/' + param.name + '.key', param.key, function(err) {
		if(err) {
			return true;
		} else {
			fs.writeFile(cadir + '/' + param.name + '/' + param.name + '.crt', param.cert, function(err) {
				if(err) {
					return true;
				} else {
					fs.writeFile(cadir + '/' + param.name + '/' + param.name + '.chain', param.chain, function(err) {
						if(err) {
							return true;
						} else {
							return false;
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
