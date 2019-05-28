var ocsplib = require('../lib/ocsp_checker.js');
var fs = require('fs');

var ocsp = new ocsplib();

var netcertoptions = {
	hostname: 'google.com',
	port: 443,
	starttls: false,
	protocol: 'https'
}

ocsp.getCertFromNetwork(netcertoptions, function(err, response, cmd) {
	if(err) {
		console.log(err);
	} else {
		console.log(response);
		console.log(cmd);
	}
});

/*fs.readFile('./test.crt', function(err, contents) {
	//console.log(contents);
	ocsp.query(contents.toString(), function(err, resp, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(resp);
			//for(var i = 0; i <= cmd.ca.length - 1; i++) {
			//	console.log(cmd.ca[i]);
			//}
			//console.log(cmd.cert);
		}
	});
});*/
