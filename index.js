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

app.use('/js/bootstrap',  express.static(__dirname + '/node_modules/bootstrap/dist/js'));
app.use('/js/moment', express.static('./node_modules/moment/min'));
app.use('/js/jquery', express.static('./node_modules/jquery/dist'));
app.use('/js/jquery-ui', express.static('./node_modules/jquery-ui/dist'));
app.use('/js/tempusdominus-bootstrap-3', express.static('./node_modules/tempusdominus-bootstrap-3/build/js'));
app.use('/js/tempusdominus-core', express.static('./node_modules/tempusdominus-core/build/js'));
app.use('/js/popper.js', express.static('./node_modules/popper.js/dist/umd'));
//app.use('/js/fontawesome-free', express.static('./node_modules/@fortawesome/fontawesome-free/js'));
app.use('/css/tempusdominus-bootstrap-3', express.static('./node_modules/tempusdominus-bootstrap-3/build/css'));
app.use('/css/bootstrap',  express.static(__dirname + '/node_modules/bootstrap/dist/css'));
app.use('/css/fonts',  express.static(__dirname + '/node_modules/bootstrap/dist/fonts'));
app.use('/css/jquery-ui',  express.static(__dirname + '/node_modules/jquery-ui/dist'));
app.use('/css/fontawesome-free', express.static('./node_modules/@fortawesome/fontawesome-free/css'));
app.use('/css/webfonts', express.static('./node_modules/@fortawesome/fontawesome-free/webfonts'));
app.use('/images',  express.static(__dirname + '/images'));
app.use('/static',  express.static(__dirname + '/static'));

//app.use(express.static('files'))app.use('/api/auth', require('./api/auth'));

opensslcap.getCapabilities(function(err, capabilities) {
	function getTemplate() {
		return template = {
			title: "CertificateTools.com X509 Certificate Generator",
			certtemplates: certtemplates,
			javascripttemplates: JSON.stringify(certtemplates, null, 4),
			capabilities: capabilities,
			hosted: config.hosted,
			header: html.header.join('\r\n')
		}
	}
	//console.log(template);
	app.get('/', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		let template = getTemplate();
		res.render('index.html', template);
	});

	app.get('/test', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		let template = getTemplate();
		res.render('test.html', template);
	});

	app.get('/ocsp_checker', function(req, res) {
		//let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		//console.log('HTTPS connection from ' + ip);
		//res.render('ocsp_checker.html', template);
		res.redirect(301, '/ocsp-checker')
    });

	app.get('/ocsp-checker', function(req, res) {
		console.log(req.query);
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		/*let url = req.url;
		let ocsporrev = url.substring(1).split('-')[0];
		ocsporrev = ocsporrev.toUpperCase()
		console.log(ocsporrev);*/
		let template = getTemplate();
		template.title = 'OCSP Checker';
		if(req.query.hasOwnProperty('hostname')) {
			template.hostname = req.query.hostname;
		}/* else {
			template.hostname = '';
		}*/
		res.render('ocsp_checker.html', template);
	});

	app.get('/test-post-quantum-cryptography', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		/*let url = req.url;
		let ocsporrev = url.substring(1).split('-')[0];
		ocsporrev = ocsporrev.toUpperCase()
		console.log(ocsporrev);*/
		let template = getTemplate();
		template.title = 'Test Post-Quantum Readiness';
		if(req.query.hasOwnProperty('hostname')) {
			template.hostname = req.query.hostname;
		}
		res.render('test_post_quantum_cryptography.html', template);
	});
	
	app.get('/revocation-checker', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log(req.url);
		console.log('HTTPS connection from ' + ip);
		/*let url = req.url;
		let ocsporrev = url.substring(1).split('-')[0];
		ocsporrev = ocsporrev.charAt(0).toUpperCase() + ocsporrev.slice(1);
		console.log(ocsporrev);*/
		let template = getTemplate();
		template.title = 'Revocation Checker';
		res.render('ocsp_checker.html', template);
	});

	app.get('/download-certificates', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log(req.url);
		console.log('HTTPS connection from ' + ip);
		/*let url = req.url;
		let ocsporrev = url.substring(1).split('-')[0];
		ocsporrev = ocsporrev.charAt(0).toUpperCase() + ocsporrev.slice(1);
		console.log(ocsporrev);*/
		let template = getTemplate();
		template.title = 'Download Certificates';
		res.render('download_certificates.html', template);
	});
	
	app.get('/csr-generator', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		let template = getTemplate();
		res.render('csr_generator.html', template);
    });
	
	app.get('/manage-certs', function(req, res) {
		let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
		console.log('HTTPS connection from ' + ip);
		let template = getTemplate();
		res.render('manage_certs.html', template);
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
