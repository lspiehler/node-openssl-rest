module.exports = {
	apps: [{
		name: "node-openssl-rest",
		script: "./index.js",
		env: {
			PUBLICHTTP: false,
			CAIPDIR: false,
			HTTPPORT: 8080,
			HTTPSPORT: 8443,
			HOSTED: false
		}
	}]
}
