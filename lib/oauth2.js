/**
 * Module dependencies.
 */
var util = require('util'),
    _ = require('lodash'),
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
 *   - `redirectUri`   URL to which Ghost will redirect the user after granting authorization
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

    this.retries = options.retries || 10;
    this.retryTimeout = options.retryTimeout ||1000 * 5;

    if (!this.blogUri) {
        throw new errors.IncorrectUsageError({
            message: 'Please add a blogUri.'
        });
    }

    options.authorizationURL = this.url + '/oauth2/authorize';
    options.tokenURL = this.url + '/oauth2/token';

    this._updateClientUrl = this.url + '/oauth2/client';
    this._registerURL = this.url + '/oauth2/client';
    this._userProfileURL = this.url + '/oauth2/userinfo';
    this._changePasswordURL = this.url + '/oauth2/password';
    this._updateRedirectUri = this.url + '/oauth2/client/redirect';

    // this is required from OAuth2Strategy, but because of dynamic client registration we set a placeholder
    options.clientID = options.clientID || 'clientID';
    options.clientSecret = options.clientSecret || 'clientSecret';

    // The option callbackURL is no invention of Ghost, it's a requirement of OAuth2Strategy
    // OAuth2Strategy is taking care of assigning _callbackURL to the current instance
    // We support passing redirectUri as option
    options.callbackURL = options.callbackURL || options.redirectUri;
    OAuth2Strategy.call(this, options, verify);

    // keep here!
    this.name = 'ghost';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.makeRequest = function makeRequest(options, done) {
    var self = this,
        tries = _.isUndefined(options.tries) ? this.retries : options.tries;

    self._oauth2._request(
        options.method || 'GET',
        options.url,
        {"content-type": "application/json"},
        JSON.stringify(options.body || {}),
        null,
        function (err, body) {
            debug(err);

            if (err) {
                if (tries > 0) {
                    // CASE: retry, service is down or not reachable
                    if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
                        debug(err.code);
                        debug('Trying to retry request: ' + options.url);
                        debug('Tries: ' + tries);

                        var timeout = setTimeout(function () {
                            clearTimeout(timeout);

                            options.tries = tries - 1;
                            self.makeRequest(options, done);
                        }, self.retryTimeout);

                        return;
                    }
                }

                // CASE: error is nested in data property
                if (err.data) {
                    try {
                        err = JSON.parse(err.data);

                        // JSONAPI format?
                        if (err.errors) {
                            err = errors.utils.deserialize(err);
                        } else {
                            if (err.name) {
                                err = new errors[err.name]({err: err});
                            } else {
                                err = new errors.InternalServerError({err: err});
                            }
                        }

                        err.help = 'Encountered error for Ghost Auth request: ' + options.url;
                        done(err);
                    } catch (err) {
                        debug(err);

                        done(new errors.InternalServerError({
                            message: 'Encountered unexpected error for Ghost Auth request: ' + options.url
                        }));
                    }
                }
                // CASE: request library error e.q. connection refused
                else {
                    done(new errors.IgnitionError({
                        statusCode: err.statusCode,
                        code: err.code,
                        message: err.message,
                        help: 'Encountered unexpected error for Ghost Auth request: ' + options.url,
                        errorType: err.errorType || err.name
                    }));
                }
            }

            try {
                body = JSON.parse(body || null);
                return done(null, body);
            } catch (err) {
                debug(err);

                return done(new errors.InternalServerError({
                    message: 'Encountered unexpected error for Ghost Auth request: ' + options.url
                }));
            }
        });
};

Strategy.prototype.authenticate = function authenticate(req, options) {
    options || (options = {});

    var oldHint = options.loginHint;
    options.loginHint = req.query.login_hint;
    OAuth2Strategy.prototype.authenticate.call(this, req, options);
    options.loginHint = oldHint
};

Strategy.prototype.registerClient = function registerClient(options) {
    options = options || {};

    var self = this,
        name = options.name,
        description = options.description;

    if (!name) {
        return Promise.reject(new errors.IncorrectUsageError({
            message: 'Please forward name property.'
        }));
    }

    return new Promise(function (resolve, reject) {
        self.makeRequest({
            method: 'POST',
            url: self._registerURL,
            body: {
                name: name,
                description: description,
                redirect_uri: self._callbackURL,
                blog_uri: self.blogUri
            }
        }, function (err, body) {
            if (err) {
                return reject(err);
            }

            debug('registered client', body);
            resolve(body);
        });
    });
};

/**
 * PUT request to update the registered client
 */
Strategy.prototype.updateClient = function updateClient(options) {
    var self = this;

    debug('updateClient: ' + JSON.stringify(options));

    return new Promise(function (resolve, reject) {
        self.makeRequest({
            method: 'PUT',
            url: self._updateClientUrl,
            body: _.omit({
                client_id: options.clientId,
                client_secret: options.clientSecret,
                blog_uri: options.blogUri,
                redirect_uri: options.redirectUri,
                name: options.name,
                description: options.description
            }, _.isUndefined)
        }, function (err, body) {
            if (err) {
                return reject(err);
            }

            debug('updated client: ', body);
            resolve(body);
        });
    });
};

/**
 * If you register a client and your blog url changes afterwards, you can use this function to update the callbackURL.
 * @deprecated
 */
Strategy.prototype.changeCallbackURL = function changeCallbackURL(options) {
    options = options || {};

    var self = this,
        redirect_uri = options.redirectUri,
        clientId = options.clientId,
        clientSecret = options.clientSecret;

    debug('changeCallbackURL: ' + JSON.stringify(options));

    return new Promise(function (resolve, reject) {
        self.makeRequest({
            method: 'POST',
            url: self._updateRedirectUri,
            body: {
                redirect_uri: redirect_uri,
                client_id: clientId,
                client_secret: clientSecret
            }
        }, function (err, body) {
            if (err) {
                return reject(err);
            }

            debug('changed client callback url', body);
            resolve(body);
        });
    });
};

Strategy.prototype.setClient = function setClient(client) {
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
Strategy.prototype.userProfile = function userProfile(accessToken, done) {
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
            return done(new errors.InternalServerError());
        }
    });
};

Strategy.prototype.changePassword = function changePassword(options, done) {
    options = options || {};

    var accessToken = options.accessToken,
        oldPassword = options.oldPassword,
        newPassword = options.newPassword,
        self = this;

    return new Promise(function (resolve, reject) {
        self.makeRequest({
            method: 'PUT',
            url: self._changePasswordURL,
            body: {
                access_token: accessToken,
                oldPassword: oldPassword,
                newPassword: newPassword
            }
        }, function (err, body) {
            if (err) {
                return reject(err);
            }

            debug('change password', body);
            resolve(body);
        });
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
