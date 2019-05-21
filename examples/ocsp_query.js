var ocsplib = require('../lib/ocsp_checker.js');

var ocsp = new ocsplib();

var netcertoptions = {
	hostname: 'google.com',
	port: 443,
	starttls: false,
	protocol: 'https'
}

ocsp.getCertFromNetwork(netcertoptions, function(err, response) {
	console.log(response);
});