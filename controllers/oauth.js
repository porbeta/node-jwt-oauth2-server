var fs = require('fs');
var base64url = require('base64url');
var deepcopy = require("deepcopy");
var jwt = require('jsonwebtoken');

var oauthValidator = require('../validation/oauth');

exports.getTokenKey = function(req, res) {
	var publicKey = fs.readFileSync('ssl/token.auth.example.com.key.pub.pem', 'utf8'); 
	
	res.json({
		alg: "sha256WithRSA",
		value: publicKey
	});
}

// https://tools.ietf.org/html/rfc6749#section-4.1.2.1
exports.getToken = function(req, res) {
	var ret = oauthValidator.validateGetToken(req, res);
	
	if(ret == null) {
		var claims = JSON.parse(base64url.decode(req.body.client_assertion.split(".")[1]));
		var payload = deepcopy(claims);
		
		var privateKey = fs.readFileSync('ssl/token.auth.example.com.key.pem');
		var privateKeyPassword = process.env.PRIVATE_KEY_PASSWORD;
		
		payload.client_id = claims.sub;
		payload.client_credentials = req.body.client_credentials;
		payload.scope = req.body.scope;
		payload.authorities = "BASICRESTRD,BASICRESTMN" // TODO: Change this logic so that it is not hard coded
		
		
		var accessToken = jwt.sign(payload, { key: privateKey, passphrase: privateKeyPassword }, { algorithm: 'RS256'});
		
		res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 });

	}
	else {
		res.status(ret.status).json(ret.json);
	}
}

