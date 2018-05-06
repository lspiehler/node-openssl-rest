var config = {
	
	//for public hosted, create CA directory for source IP
	caIPDir: false,
	
	httpport: 8080,
	
	httpsport: 8443,
	
	//will enable ocsp and aia
	publichttp: process.env.PUBLICHTTP || false,
	
}

module.exports = config;
