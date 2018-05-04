var express = require('express'),
router = express.Router();
var openssl = require('../lib/openssl.js');
var multer  = require('multer')
var upload = multer();
var fs = require('fs');
var config = require('../config.js');

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

module.exports = router
