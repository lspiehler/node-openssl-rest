//var openssl = require('./lib/openssl.js')
var express_ssl = require('./lib/express_ssl.js')
var config = require('./config.js');
var html = require('./html.js');
var express = require('express')
//var multer  = require('multer');
var bodyParser = require('body-parser')
//var https = require('https');
var mustacheExpress = require('mustache-express');
var app = express();
var httpapp = express();
var certtemplates = require('./templates.js');
var opensslcap = require('./lib/openssl_capabilities.js');
const fs = require('fs');

if (fs.existsSync('./ca/global')) {
	console.log('exists');
} else {
	fs.mkdirSync('./ca/global');
}

console.log('CAIPDIR is set to "' + config.caIPDir + '"');
console.log('HOSTED is set to "' + config.hosted + '"');
console.log('HTTPPORT is set to "' + config.httpport + '"');
console.log('HTTPSPORT is set to "' + config.httpsport + '"');
console.log('PUBLICHTTP is set to "' + config.publichttp + '"');

express_ssl.getSSL(function(sslOptions) {
	var server = require('https').createServer(sslOptions, app).listen(config.httpsport);
});

var httpserver = require('http').createServer(httpapp).listen(config.httpport);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies.

// Register '.mustache' extension with The Mustache Express
app.engine('html', mustacheExpress());
app.set('view engine', 'html');

app.use('/bower_components',  express.static(__dirname + '/bower_components'));
app.use('/images',  express.static(__dirname + '/images'));

//app.use(express.static('files'))app.use('/api/auth', require('./api/auth'));

opensslcap.getCapabilities(function(err, capabilities) {
	var template = {
		title: "CertificateTools.com X509 Certificate Generator",
		certtemplates: certtemplates,
		javascripttemplates: JSON.stringify(certtemplates, null, 4),
		capabilities: capabilities,
		hosted: config.hosted,
		header: html.header.join('\r\n')
	}
	//console.log(template);
	app.get('/', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		res.render('index.html', template);
	});

	app.get('/ocsp_checker', function(req, res) {
                let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
                console.log('HTTPS connection from ' + ip);
                res.render('ocsp_checker.html', template);
        });
	
	app.get('/csr_generator', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		res.render('csr_generator.html', template);
        });

	app.use('/', express.static(__dirname + '/views'));
});

app.get('/newui', function(req, res) {
        let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        console.log('HTTPS connection from ' + ip + ', redirecting to root');
        res.redirect('/');
});

app.get('/ca', function(req, res) {
        let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        console.log('HTTPS connection from ' + ip + ', tshirt CA download');
        res.redirect('/ca.crt');
});

app.use(function(req, res, next) {
	res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
	//res.header('Content-Type', 'application/json');
	//res.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
	next();
});

app.use('/api/openssl', require('./api/openssl'));
httpapp.use('/public/', require('./api/public'));
