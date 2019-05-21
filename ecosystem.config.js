module.exports = {
	apps: [{
		name: "node-openssl-rest",
		script: "./index.js",
		env: {
			PUBLICHTTP: "certificatetools.com:8080"
		}
	}]
}
