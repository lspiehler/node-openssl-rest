var config = require('./config.js');

var html = {
	
	header: ['<nav class="navbar navbar-default navbar-fixed-top" role="navigation">',
		'	<div class="container-fluid" id="navfluid">',
		'		<div class="navbar-header">',
		'			<a class="navbar-brand" href="/">CertificateTools.com</a>',
		'			<button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#navigationbar">',
		'			<span class="sr-only">Toggle navigation</span>',
		'			<span class="icon-bar"></span>',
		'			<span class="icon-bar"></span>',
		'			<span class="icon-bar"></span>',
		'			</button>',
		'		</div>',
		'		<div class="collapse navbar-collapse" id="navigationbar">',
		'			<ul class="nav navbar-nav">',
		'			<li class="dropdown">',
		'				<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">Revocation <span class="caret"></span></a>',
		'				<ul class="dropdown-menu">',
		'					<li><a href="/ocsp-checker">OCSP Checker</a></li>',
		'                   <li><a href="/revocation-checker">Revocation Checker</a></li>',
		'				</ul>',
		'			</li>',
		'			<li class="dropdown">',
		'               <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">Generators <span class="caret"></span></a>',
		'               <ul class="dropdown-menu">',
		'                   <li><a href="/csr-generator">CSR Generator</a></li>',
		'                   <li><a href="/">Certificate Generator</a></li>',
		'               </ul>',
		'           </li>',
		'			<li class="dropdown">',
		'               <a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">SSL/TLS <span class="caret"></span></a>',
		'               <ul class="dropdown-menu">',
		'                   <li><a href="/test-post-quantum-cryptography">Test Post Quantum TLS Handshake</a></li>',
		'               </ul>',
		'           </li>'
	]
}

if(config.hosted==false) {
	html.header.push('<li><a href="/manage-certs">Manage Certificates</a></li>')
}

html.header.push('		</ul>'),
html.header.push('		<!--<ul class="nav navbar-nav navbar-right">'),
html.header.push('			<li><a id="authbutton" href="javascript: loginButton();">Login</a></li>'),
html.header.push('		</ul>-->'),
html.header.push('		</div><!-- /.navbar-collapse -->'),
html.header.push('	</div><!-- /.container-fluid -->'),
html.header.push('</nav>');

module.exports = html;
