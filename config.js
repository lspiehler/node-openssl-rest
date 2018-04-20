var config = {
	
	//email address to send usage data
	emailParams: false,
	
	//for public hosted, create CA directory for source IP
	caIPDir: false,
	
	nodemailertransportparams: {
		host: '127.0.0.1',
		port: 25,
		secure: false
	},
	
	nodemailermailoptions: {
		from: '"Node OpenSSL Rest" <example@address.com>', // sender address
        to: 'example@address.com', // list of receivers
        subject: 'node-openssl-rest data', // Subject line
        //text: 'Hello world?', // plain text body
        //html: '<b>Hello world?</b>' // html body
	}
	
}

module.exports = config;