require('dotenv').config()

var config = {
	
	//for public hosted, create CA directory for source IP
	caIPDir: process.env.CAIPDIR || false,

	hosted: process.env.HOSTED || false,
	
	httpport: process.env.HTTPPORT || 8080,
	
	httpsport: process.env.HTTPSPORT || 8443,
	
	//will enable ocsp and aia
	publichttp: process.env.PUBLICHTTP || false,

	opensearchhost: process.env.OPENSEARCHHOST || false,

	opensearchport: process.env.OPENSEARCHPORT || false,

	opensearchport: process.env.SSCEPCONTAINER || 'node-sscep',
	
	opensslbinpath: process.env.OPENSSLBINPATH || '/opt/openssl32/bin/openssl'
	//opensslbinpath: process.env.OPENSSLBINPATH || 'openssl'
	//opensslbinpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
	
}

module.exports = config;

//minimal windows example
//SET OPENSSLBINPATH=C:\Program Files\OpenVPN\bin\openssl.exe&&SET PUBLICHTTP=192.168.164.110:8080&& node index.js

//minimal Linux example
//export HTTPPORT=9080&&export HTTPSPORT=9443&&node index.js