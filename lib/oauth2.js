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
    this.retryHook = options.retryHook;

    this.retries = options.retries || 10;
    this.retryTimeout = options.retryTimeout ||1000 * 5;

    if (!this.blogUri) {
        throw new errors.IncorrectUsageError({
            message: 'Please add a blogUri.'
        });
    }

    options.authorizationURL = this.url + '/oauth2/authorize/';
    options.tokenURL = this.url + '/oauth2/token/';

    this._updateClientUrl = this.url + '/oauth2/client/';
    this._registerURL = this.url + '/oauth2/client/';
    this._userProfileURL = this.url + '/oauth2/userinfo/';
    this._changePasswordURL = this.url + '/oauth2/password/';
    this._updateRedirectUri = this.url + '/oauth2/client/redirect/';

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

    debug('make request', JSON.stringify(options));

    self._oauth2._request(
        options.method || 'GET',
        options.url,
        options.headers || {"content-type": "application/json"},
        options.body ? JSON.stringify(options.body) : null,
        options.accessToken,
        function (err, body) {
            debug(err);
            debug(body);

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

                        self.retryHook && self.retryHook(new errors.IgnitionError({
                            errorType: 'ServiceIsDown',
                            message: 'Encountered unexpected error for Ghost Auth request: ' + options.url,
                            code: err.code,
                            help: 'Please verify that the configured url is correct.',
                            context: 'Retry count: ' + tries
                        }));

                        return;
                    }
                }

                // CASE: error is nested in data property
                if (err.data) {
                    try {
                        err = JSON.parse(err.data);
                        err = errors.utils.deserialize(err);

                        err.help = 'Encountered error for Ghost Auth request: ' + options.url;
                        done(err);
                    } catch (err) {
                        debug(err);

                        done(new errors.IgnitionError({
                            message: 'Encountered unexpected error for Ghost Auth request: ' + options.url,
                            errorType: 'JSONParseError',
                            help: 'Please try again.',
                            context: 'Response: ' + err.data
                        }));
                    }
                }
                // CASE: request library error e.q. connection refused
                else {
                    return done(new errors.IgnitionError({
                        statusCode: err.statusCode,
                        code: err.code,
                        message: err.message,
                        help: 'Encountered unexpected error for Ghost Auth request: ' + options.url,
                        errorType: err.errorType || err.name
                    }));
                }
            }

            // CASE: e.g. auth url is wrong
            if (!body) {
                return done(new errors.BadRequestError({
                    message: 'Encountered unexpected error for Ghost Auth request: ' + options.url,
                    help: 'The response of the service could not be understood.'
                }));
            }

            try {
                body = JSON.parse(body || null);
                return done(null, body);
            } catch (err) {
                debug(err);

                return done(new errors.IgnitionError({
                    errorType: 'JSONParseError',
                    message: 'Encountered unexpected error for Ghost Auth request: ' + options.url,
                    help: 'Please try again.',
                    context: 'Response: ' + body
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

Strategy.prototype.setClient = function setClient(client) {
    this._oauth2._clientId = client.client_id;
    this._oauth2._clientSecret = client.client_secret;
};

/**
 * Retrieve user profile via access token.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function userProfile(accessToken, done) {
    if (!accessToken) {
        return done(new errors.NoPermissionError());
    }

    this.makeRequest({
        url: this._userProfileURL,
        headers: {},
        accessToken: accessToken
    }, function (err, body) {
        if (err) {
            return done(err);
        }

        debug('get user profile response', body);
        done(null, body);
    });
};

/**
 * Retrieve user profile via identity id and client credentials..
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfileByIdentityId = function userProfileByIdentityId(identityId, done) {
    if (!identityId) {
        return done(new errors.NoPermissionError());
    }

    this.makeRequest({
        url: this._userProfileURL + identityId + '/?client_id=' + this._oauth2._clientId + '&client_secret=' + this._oauth2._clientSecret,
        headers: {}
    }, function (err, body) {
        if (err) {
            return done(err);
        }

        debug('get user profile response', body);
        done(null, body);
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
