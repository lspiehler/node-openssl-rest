var ocsplib = require('../lib/ocsp_checker.js');
var fs = require('fs');

var ocsp = new ocsplib();

var netcertoptions = {
	hostname: 'google.com',
	port: 443,
	starttls: false,
	protocol: 'https'
}

//ocsp.getCertFromNetwork(netcertoptions, function(err, response) {
//	console.log(response);
//});

fs.readFile('./google.crt', function(err, contents) {
	//console.log(contents);
	ocsp.query(contents.toString(), function(err, resp, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(resp);
		}
	});
});
