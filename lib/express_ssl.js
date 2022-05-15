var os = require('os');
var openssl = require('./openssl.js')
var fs = require('fs');

var ssloptions = {}

var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

var csroptions = {
	hash: 'sha512',
	subject: {
		countryName: 'US',
		organizationName: 'node-openssl-rest',
		commonName: [
			os.hostname()
		],
		emailAddress: 'admin@emil.md'
	},
	extensions: {
		keyUsage: {
			usages: [
				'digitalSignature',
				'keyEncipherment'
			]
		},
		extendedKeyUsage: {
			critical: true,
			usages: [
				'serverAuth',
				'clientAuth'
			]	
		},
		SANs: {
			DNS: [
				os.hostname()
			]
		}
	}
}

var getKey = function(callback) {
	var keypath = './certs/key.pem';
	fs.stat(keypath, function(err, stat) {
		if(err == null) {
			fs.readFile(keypath, 'utf8', function(err, contents) {
				callback(false, contents);
				//console.log(contents);
			});
		} else if(err.code == 'ENOENT') {
			// file does not exist
			openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
				fs.writeFile(keypath, key, function() {
					callback(false, key);
				});
			});
		} else {
			callback(err, false);
			console.log('Some other error: ', err.code);
		}
	});
}

var getCert = function(key, callback) {
	var certpath = './certs/cert.pem';
	fs.stat(certpath, function(err, stat) {
		if(err == null) {
			fs.readFile(certpath, 'utf8', function(err, contents) {
				callback(false, contents);
			});
		} else if(err.code == 'ENOENT') {
			// file does not exist
			openssl.generateCSR(csroptions, key, false, function(err, csr, cmd) {
				if(err) console.log(err);
				openssl.selfSignCSR(csr, csroptions, key, false, function(err, crt, cmd) {
					if(err) console.log(err);
					fs.writeFile(certpath, crt, function() {
						callback(false, crt);
					});
				});
			});
		} else {
			callback(err, false);
			console.log('Some other error: ', err.code);
		}
	});
}

var expressSSL = function(callback) {
	getKey(function(err, key) {
		ssloptions.key = key;
		getCert(key, function(err, crt){
			ssloptions.cert = crt;
			
			ssloptions.cipher = [
					"ECDHE-ECDSA-AES256-GCM-SHA384",
					"ECDHE-RSA-AES256-GCM-SHA384",
					"ECDHE-ECDSA-AES256-SHA384",
					"ECDHE-RSA-AES256-SHA384",
					"ECDHE-ECDSA-AES256-GCM-SHA256",
					"ECDHE-RSA-AES256-GCM-SHA256",
					"ECDHE-ECDSA-AES256-SHA256",
					"ECDHE-RSA-AES256-SHA256",
					"DHE-RSA-AES256-GCM-SHA384",
					"DHE-RSA-AES256-GCM-SHA256",
					"DHE-RSA-AES256-SHA256",
					"ECDHE-ECDSA-AES128-GCM-SHA256",
					"ECDHE-RSA-AES128-GCM-SHA256",
					"ECDHE-ECDSA-AES128-SHA256",
					"ECDHE-RSA-AES128-SHA256",
					"ECDHE-ECDSA-AES128-SHA",
					"ECDHE-RSA-AES128-SHA",
					"DHE-RSA-AES128-GCM-SHA256",
					"DHE-RSA-AES128-SHA256",
					"DHE-RSA-AES128-SHA",
					"AES256-GCM-SHA384",
					"AES256-SHA256",
					"AES128-GCM-SHA256",
					"AES128-SHA256",
					"AES128-SHA",
					"!aNULL",
					"!eNULL",
					"!EXPORT",
					"!DES",
					"!RC4",
					"!MD5",
					"!PSK",
					"!SRP",
					"!CAMELLIA"
			].join(':')

			ssloptions.honorCipherOrder = true;
			
			callback(ssloptions);
		});
	});
}

module.exports = {
	getSSL: function(callback) {
		expressSSL(callback);
	}
}