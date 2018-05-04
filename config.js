var config = {
	
	//email address to send usage data
	emailParams: false,
	
	//for public hosted, create CA directory for source IP
	caIPDir: false,
	
	httpport: 8080,
	
	httpsport: 8443,
	
	//will enable ocsp and aia
	publichttp: process.env.PUBLICHTTP || false,
	
	nodemailertransportparams: {
		host: '127.0.0.1',
		port: 25,
		secure: false
	},
	
	nodemailermailoptions: {
		from: '"Node OpenSSL Rest" <notifications@notjustnetworks.com>', // sender address
        to: 'notifications@notjustnetworks.com', // list of receivers
        subject: 'node-openssl-rest data', // Subject line
        //text: 'Hello world?', // plain text body
        //html: '<b>Hello world?</b>' // html body
	}
	
}

module.exports = config;