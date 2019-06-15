const HOUR = 1000 * 60 * 60 * 23;
var cas = {}

module.exports = {
	getRequest: function(ca, serial) {
		if(cas[ca]) {
			if(cas[ca][serial]) {
				let now = new Date();
				if(now - HOUR > cas[ca][serial].date) {
					//console.log('cache old');
					return false;
				} else {
					//console.log(cas);
					//console.log('cache fresh');
					return cas[ca][serial];
				}
			}
		}
		return false;
	},
	
	addResponse: function(ca, serial, resp) {
		if(cas[ca]) {
			if(cas[ca][serial]) {
				cas[ca][serial] = {
					date: new Date(),
					response: resp
				}
				return true;
			} else {
				cas[ca][serial] = {
					date: new Date(),
					response: resp
				}
				return true;
			}
		} else {
			var cert = {};
			cert[serial] = {
				date: new Date(),
				response: resp
			}
			cas[ca] = cert;
			return true;
		}
	},
	
	clearCache: function() {
		cas = {};
		return true;
	}
}