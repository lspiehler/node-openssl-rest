var email = {
	
	//email address to send usage data
	emailParams: false,
	
	nodemailertransportparams: {
		host: 'notjustnetworks.com',
		port: 465,
		secure: true
	},
	
	nodemailermailoptions: {
		from: '"Node OpenSSL Rest" <notifications@notjustnetworks.com>', // sender address
        to: 'notifications@notjustnetworks.com', // list of receivers
        subject: 'node-openssl-rest data', // Subject line
        //text: 'Hello world?', // plain text body
        //html: '<b>Hello world?</b>' // html body
	}
	
}

module.exports = email;
