var express = require('express'), 
router = express.Router();
var openssl = require('../lib/openssl.js');
var multer  = require('multer')
var upload = multer();

/*var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}*/

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
		console.log(pkcs7);
		res.send(pkcs7);
	});
});

router.post('/uploadPrivateKey', upload.single('file'), function(req, res) {
	//console.log(req.file);
	var password = req.body.password;
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

router.post('/generateCSR', function(req, res) {
	var key = req.body.key;
	var keypass = req.body.keypass;
	var csroptions = req.body.options;
	//console.log(csroptions);
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.generateCSR(csroptions, key, keypass, function(err, csr, cmd) {
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
	var key = req.body.key;
	var keypass = req.body.keypass;
	var csroptions = req.body.options;
	var csr = req.body.csr;
	//console.log(req.body);
	//res.json(req.body);
	//return;
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.CASignCSR(req.body.csr, req.body.options, req.body.ca.cert ,req.body.ca.key, req.body.ca.keypass, function(err, crt, cmd) {
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

module.exports = router