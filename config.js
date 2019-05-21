var config = {
	
	//for public hosted, create CA directory for source IP
	caIPDir: process.env.CAIPDIR || false,

	hosted: process.env.HOSTED || false,
	
	httpport: process.env.HTTPPORT || 8080,
	
	httpsport: process.env.HTTPSPORT || 8443,
	
	//will enable ocsp and aia
	publichttp: process.env.PUBLICHTTP || false,
	
}

module.exports = config;
