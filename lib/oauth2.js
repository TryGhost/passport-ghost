/**
 * Module dependencies.
 */
var util = require('util'),
    Promise = require('bluebird'),
    debug = require('ghost-ignition').debug('oauth2'),
    errors = require('ghost-ignition').errors,
    OAuth2Strategy = require('passport-oauth2'),
    InternalOAuthError = require('passport-oauth2').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * The Ghost authentication strategy authenticates requests by delegating to
 * Ghost using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Ghost application's client id
 *   - `clientSecret`  your Ghost application's client secret
 *   - `callbackURL`   URL to which Ghost will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new GhostStrategy({
 *         clientID: '1234',
 *         clientSecret: 'secret'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    this.url = options.url || 'https://auth.ghost.org';
    this.blogUri = options.blogUri;

    if (!this.blogUri) {
        throw new errors.IncorrectUsageError({
            message: 'Please add a blogUri.'
        });
    }

    options.authorizationURL = this.url + '/oauth2/authorize';
    options.tokenURL = this.url + '/oauth2/token';
    this._registerURL = this.url + '/oauth2/client';
    this._userProfileURL = this.url + '/oauth2/userinfo';
    this._changePasswordURL = this.url + '/oauth2/password';
    this._updateRedirectUri = this.url + '/oauth2/client/redirect';

    // this is required from OAuth2Strategy, but because of dynamic client registration we set a placeholder
    options.clientID = options.clientID || 'clientID';
    options.clientSecret = options.clientSecret || 'clientSecret';

    // The option callbackURL is no invention of Ghost, it's a requirement of OAuth2Strategy
    // OAuth2Strategy is taking care of assigning _callbackURL to the current instance
    OAuth2Strategy.call(this, options, verify);

    // keep here!
    this.name = 'ghost';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.authenticate = function (req, options) {
    options || (options = {});

    var oldHint = options.loginHint;
    options.loginHint = req.query.login_hint;
    OAuth2Strategy.prototype.authenticate.call(this, req, options);
    options.loginHint = oldHint
};

Strategy.prototype.registerClient = function (options) {
    options = options || {};

    var self = this,
        clientName = options.clientName || 'client';

    return new Promise(function (resolve, reject) {
        self._oauth2._request(
            "POST",
            self._registerURL,
            {"content-type": "application/json"},
            JSON.stringify({
                client_name: clientName,
                redirect_uri: self._callbackURL,
                blog_uri: self.blogUri
            }),
            null,
            function (err, body) {
                if (err) {
                    debug(err);
                    return reject(new errors.BadRequestError({err: err}));
                }

                try {
                    body = JSON.parse(body || null);

                    debug('registered client', body);
                    return resolve(body);
                } catch (err) {
                    debug(err);
                    return reject(new errors.BadRequestError({err: err}));
                }
            });
    });
};

/**
 * If you register a client and your blog url changes afterwards, you can use this function to update the callbackURL.
 */
Strategy.prototype.changeCallbackURL = function (options) {
    options = options || {};

    var self = this,
        redirect_uri = options.callbackURL,
        clientId = options.clientId,
        clientSecret = options.clientSecret;

    debug('changeCallbackURL: ' + JSON.stringify(options));

    return new Promise(function (resolve, reject) {
        self._oauth2._request(
            "POST",
            self._updateRedirectUri,
            {"content-type": "application/json"},
            JSON.stringify({
                redirect_uri: redirect_uri,
                client_id: clientId,
                client_secret: clientSecret
            }),
            null,
            function (err, body) {
                if (err) {
                    debug(err);
                    return reject(new errors.BadRequestError({err: err}));
                }

                try {
                    body = JSON.parse(body || null);

                    debug('changed client callback url', body);
                    return resolve(body);
                } catch (err) {
                    debug(err);
                    return reject(new errors.BadRequestError({err: err}));
                }
            });
    });
};

Strategy.prototype.setClient = function (client) {
    this._oauth2._clientId = client.client_id;
    this._oauth2._clientSecret = client.client_secret;
};

/**
 * Retrieve user profile from Ghost.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
    debug('get user profile', accessToken);
    debug('get user profile', this._userProfileURL);

    if (!accessToken) {
        return done(new errors.NoPermissionError());
    }

    this._oauth2.get(this._userProfileURL, accessToken, function (err, body) {
        if (err) {
            debug(err);
            return done(new InternalOAuthError('failed to fetch user profile', err));
        }

        try {
            var json = JSON.parse(body || null);

            debug('get user profile response', body);
            done(null, json);
        } catch (err) {
            debug(err);
            return done(new errors.NoPermissionError({err: err}));
        }
    });
};

Strategy.prototype.changePassword = function (options, done) {
    options = options || {};

    var accessToken = options.accessToken,
        oldPassword = options.oldPassword,
        newPassword = options.newPassword,
        self = this;

    self._oauth2._request(
        "PUT",
        self._changePasswordURL,
        {"content-type": "application/json"},
        JSON.stringify({
            access_token: accessToken,
            oldPassword: oldPassword,
            newPassword: newPassword
        }),
        null,
        function (err, body) {
            if (err) {
                debug(err);
                return done(new errors.NoPermissionError({err: err}));
            }

            try {
                body = JSON.parse(body || null);

                debug('change password', body);
                return done(null, body);
            } catch (err) {
                debug(err);
                return done(new errors.NoPermissionError({err: err}));
            }
        });
};

/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports.Strategy = Strategy;
