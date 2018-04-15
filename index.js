//var openssl = require('./lib/openssl.js')
var express_ssl = require('./lib/express_ssl.js')
var express = require('express')
//var multer  = require('multer');
var bodyParser = require('body-parser')
//var https = require('https');
var mustacheExpress = require('mustache-express');
var app = express();

express_ssl.getSSL(function(sslOptions) {
	var server = require('https').createServer(sslOptions, app).listen(8443);
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support encoded bodies.

// Register '.mustache' extension with The Mustache Express
app.engine('html', mustacheExpress());
app.set('view engine', 'html');
app.set('views', __dirname + '/views');

//app.use(express.static('files'))app.use('/api/auth', require('./api/auth'));
	
app.get('/', function(req, res) {
	res.render('index.html', {"title": "CertificateTools.com CSR/Certificate Generator"});
});

app.use(function(req, res, next) {
	res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
	//res.header('Content-Type', 'application/json');
	//res.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
	next();
});

app.use('/api/openssl', require('./api/openssl'));