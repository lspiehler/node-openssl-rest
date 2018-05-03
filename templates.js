module.exports = [
	{
		name: "Web Server",
		extensions: {
			keyUsage: {
				critical: true,
				usages: [
					"digitalSignature",
					"keyEncipherment"
				]
			},
			extendedKeyUsage: {
				critical: false,
				usages: [
					"serverAuth",
					"clientAuth"
				]
			},
			basicConstraints: {
				critical: true,
				CA: false
			}
		}
	},
	{
		name: "Root Certificate Authority",
		extensions: {
			keyUsage: {
				critical: true,
				usages: [
					"keyCertSign",
					"cRLSign"
				]
			},
			/*extendedKeyUsage: {
				critical: false,
				usages: [
					"serverAuth",
					"clientAuth"
				]
			},*/
			basicConstraints: {
				critical: true,
				CA: true,
				pathlen: 1
			}
		}
	},
	{
		name: "Client Authentication",
		extensions: {
			keyUsage: {
				usages: [
					"digitalSignature"
				]
			},
			extendedKeyUsage: {
				usages: [
					"clientAuth"
				]
			}
		}
	},
	{
		name: "OCSP Signing",
		extensions: {
			keyUsage: {
				critical: true,
				usages: [
					"digitalSignature"
				]
			},
			extendedKeyUsage: {
				critical: true,
				usages: [
					"OCSPSigning"
				]
			},
			basicConstraints: {
				critical: true,
				CA: false
			}
		}
	},
	//http://www.macfreek.nl/memory/Create_a_OpenVPN_Certificate_Authority
	{
		name: "OpenVPN Server",
		extensions: {
			keyUsage: {
				usages: [
					"digitalSignature",
					"keyEncipherment"
				]
			},
			extendedKeyUsage: {
				usages: [
					"serverAuth"
				]
			},
			basicConstraints: {
				CA: false
			}
		}
	},
	{
		name: "OpenVPN Client",
		extensions: {
			keyUsage: {
				usages: [
					"digitalSignature"
				]
			},
			extendedKeyUsage: {
				usages: [
					"clientAuth"
				]
			},
			basicConstraints: {
				CA: false
			}
		}
	}
]