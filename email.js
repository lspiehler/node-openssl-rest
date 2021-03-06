var email = {

        //email address to send usage data
        emailParams: process.env.EMAILPARAMS || false,

        nodemailertransportparams: {
                host: process.env.EMAILHOST || 'notjustnetworks.com',
                port: process.env.EMAILPORT || 465,
                secure: process.env.EMAILSECURE || true
        },

        nodemailermailoptions: {
                from: process.env.EMAILFROM || '"Node OpenSSL Rest" <notifications@notjustnetworks.com>', // sender address
                to: process.env.EMAILTO || 'notifications@notjustnetworks.com', // list of receivers
                subject: process.env.EMAILSUBJECT || 'node-openssl-rest data', // Subject line
                auth: {
                        user: process.env.EMAILUSER || 'username', // generated ethereal user
                        pass: process.env.EMAILPASS || 'password' // generated ethereal password
                }
        }
}

module.exports = email;
