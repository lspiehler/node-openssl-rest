var openssl = require('./openssl.js');

capabilities = {}

module.exports = {
	getCapabilities: function(callback) {
		openssl.getAvailableCurves(function(err, curves, out) {
			if(err) {
				callback('Error getting available OpenSSL ECC curves',capabilities);
			} else {
				capabilities.curves = curves;
				callback(false,capabilities);
			}
		});
	}
}