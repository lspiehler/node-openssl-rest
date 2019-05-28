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
		'					<li><a href="/ocsp_checker">OCSP Checker</a></li>',
		'				</ul>',
		'			</li>',
		'		</ul>',
		'		<!--<ul class="nav navbar-nav navbar-right">',
		'			<li><a id="authbutton" href="javascript: loginButton();">Login</a></li>',
		'		</ul>-->',
		'		</div><!-- /.navbar-collapse -->',
		'	</div><!-- /.container-fluid -->',
		'</nav>']
	
}

module.exports = html;
