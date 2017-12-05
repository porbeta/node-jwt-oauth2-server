var express = require('express');
var router = express.Router();

var oauthController = require('../controllers/oauth');

/* GET the token key. */
router.route('/token_key').get(oauthController.getTokenKey);

/* POST to retrieve a new token. */
router.route('/token').post(oauthController.getToken);

module.exports = router;
