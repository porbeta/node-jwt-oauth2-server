var base64url = require('base64url');
var jwt = require('jsonwebtoken');

exports.validateGetToken = function(req, res) {
	var grantTypes = ['client_credentials'];
	var scopes = ['self'];
	var clientAssertionTypes = ['urn:ietf:params:oauth:client-assertion-type:jwt-bearer'];
	
	if(!hasParameters(req)
		|| !isValidParameter(req.body.grant_type, grantTypes)
		|| !isValidParameter(req.body.scope, scopes)
		|| !isValidParameter(req.body.client_assertion_type, clientAssertionTypes)) {
		
		return { status: 400, json: { error: "invalid_request", error_message: "request invalid" }};
	}
	else {
		var clientAssertion = req.body.client_assertion.split(".");
		var accessToken = req.body.client_assertion;
				
		var header = JSON.parse(base64url.decode(clientAssertion[0]));
		var claims = JSON.parse(base64url.decode(clientAssertion[1]));
		
		if(!isValidClaim(claims.iss)
			|| !isValidClaim(claims.sub)
			|| !isValidClaim(claims.exp)
			|| !isValidClaim(claims.iat)
			|| !isValidClaim(claims.nbf)
			|| !isValidClaim(claims.aud)
			|| !isValidClaim(claims.jti)) {
			
			return { status: 400, json: { error: "invalid_request", error_message: "claims invalid" }};
		}
		
		if(!isAuthenticated(claims, header, accessToken)) {
			return { status: 401, json: { error: "unauthorized_client" } }
		}
	}
	
	return null;
}

function hasParameters(req) {
	return req.body.grant_type != null && req.body.scope != null && req.body.client_assertion_type != null && req.body.client_assertion != null;
}

function isValidParameter(value, acceptedValues) {
	return value != null && acceptedValues.indexOf(value) > -1;
}

function isValidClaim(value) {
	return value != null;
}

function isAuthenticated(claims, header, accessToken) {
	if(typeof claims.aud === 'string') {
		var auds = claims.aud.split()
		
		for(singleAud in auds) {
			var resourceID = singleAud.replace(/(^\w+:|^)\/\//, '').replace(/\/$/, '');
			
			if(header.alg == "RS256") {
				try {
					var resourcePublicKey = fs.readFileSync('ssl/' + resourceID + '.key.pub.pem', 'utf8');
					var decoded = jwt.verify(accessToken, resourcePublicKey, { algorithms: ['RS256'] });
				} catch(err) {
					if(err == 'invalid signature') {
						return false;
					}
				}
			}
		}
	}
	
	return true;
}