var express = require('express'), 
router = express.Router();
var openssl = require('../lib/openssl.js')

var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

router.post('/generateRSAPrivateKey', function(req, res) {
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
		var data = {
			key: key,
			command: cmd
		}
		res.json(data);
	});
});

router.get('/generateRSAPrivateKey', function(req, res) {
	//var username = req.body.username;
	//var password = req.body.password;
	openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
		var data = {
			key: key,
			command: cmd
		}
		res.send(data);
	});
});

module.exports = router