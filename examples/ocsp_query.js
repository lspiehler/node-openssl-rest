var ocsplib = require('../lib/ocsp_checker.js');
var fs = require('fs');

var ocsp = new ocsplib();

fs.readFile('./cert.cer', function(err, contents) {
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
});