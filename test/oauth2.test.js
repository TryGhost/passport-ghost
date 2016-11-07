var oauth2 = require('../lib/oauth2'),
    sinon = require('sinon'),
    errors = require('ghost-ignition').errors,
    sandbox = sinon.sandbox.create();

describe('Ghost Oauth2', function () {
    afterEach(function () {
        sandbox.restore();
    });

    describe('instantiate', function () {
        it('no verify callback', function () {
            try {
                var ghostStrategy = new oauth2.Strategy({
                    blogUri: 'http://example.com'
                });
            } catch (err) {
                should.exist(err);
                (err instanceof TypeError).should.eql(true);
            }
        });

        it('no blog uri', function () {
            try {
                var ghostStrategy = new oauth2.Strategy({
                    callbackURL: 'http://localhost:8888/callback'
                });
            } catch (err) {
                should.exist(err);
                (err instanceof errors.IncorrectUsageError).should.eql(true);
            }
        });

        it('with callback url', function () {
            var ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true
            }, function verifyCallback() {
            });

            should.exist(ghostStrategy);
            ghostStrategy.name.should.eql('ghost');
            ghostStrategy.url.should.eql('https://auth.ghost.org');
        });

        it('with custom url', function () {
            var ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });

            should.exist(ghostStrategy);
            ghostStrategy.url.should.eql('http://my-ghost-auth-server');
        });
    });

    describe('get user profile', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('no access token', function (done) {
            ghostStrategy.userProfile(null, function (err) {
                should.exist(err);
                done();
            });
        });

        it('with access token: cant parse body', function (done) {
            sandbox.stub(ghostStrategy._oauth2, 'get', function (url, token, profileDone) {
                profileDone(null, 'body');
            });

            ghostStrategy.userProfile('access-token', function (err) {
                should.exist(err);
                done();
            });
        });

        it('with access token', function (done) {
            sandbox.stub(ghostStrategy._oauth2, 'get', function (url, token, profileDone) {
                token.should.eql('access-token');
                url.should.eql('http://my-ghost-auth-server/oauth2/userinfo');
                profileDone(null, JSON.stringify({profile: 'katharina'}));
            });

            ghostStrategy.userProfile('access-token', function (err, response) {
                should.not.exist(err);
                should.exist(response.profile);
                done();
            });
        });
    });

    describe('register client', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('error', function () {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('POST');
                url.should.eql('http://my-ghost-auth-server/oauth2/client');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                JSON.parse(body).name.should.eql('client');
                JSON.parse(body).redirect_uri.should.eql('http://localhost:8888/callback');

                requestDone({
                    statusCode: 422,
                    data: JSON.stringify(new errors.BadRequestError({
                        message: 'connection refused'
                    }))
                });
            });

            return ghostStrategy.registerClient()
                .catch(function (err) {
                    should.exist(err);
                    (err instanceof errors.IgnitionError).should.eql(true);
                });
        });

        it('no options, expect error', function () {
            return ghostStrategy.registerClient()
                .catch(function (err) {
                    (err instanceof errors.IncorrectUsageError).should.eql(true);
                });
        });

        it('with options', function () {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('POST');
                url.should.eql('http://my-ghost-auth-server/oauth2/client');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                JSON.parse(body).name.should.eql('my-blog');
                JSON.parse(body).description.should.eql('my blog description');
                JSON.parse(body).redirect_uri.should.eql('http://localhost:8888/callback');
                requestDone(null, JSON.stringify({client_id: '1'}));
            });

            return ghostStrategy.registerClient({name: 'my-blog', description: 'my blog description'})
                .then(function (response) {
                    response.client_id.should.eql('1');
                });
        });
    });

    describe('change pwd', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('error: no data', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/password');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                should.not.exist(JSON.parse(body).access_token);
                should.not.exist(JSON.parse(body).oldPassword);

                requestDone({
                    statusCode: 422,
                    data: JSON.stringify(new errors.ValidationError({
                        message: 'validation error'
                    }))
                });
            });

            ghostStrategy.changePassword(null)
                .catch(function (err) {
                    should.exist(err);
                    (err instanceof errors.IgnitionError).should.eql(true);
                    done();
                });
        });

        it('success', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/password');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                JSON.parse(body).access_token.should.eql('a');
                JSON.parse(body).oldPassword.should.eql('b');
                JSON.parse(body).newPassword.should.eql('c');

                requestDone(null, JSON.stringify({something: 'test'}));
            });

            ghostStrategy.changePassword({
                accessToken: 'a',
                oldPassword: 'b',
                newPassword: 'c'
            }).then(function (response) {
                should.exist(response.something);
                done();
            });
        });
    });

    describe('change callbackURL', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('success', function () {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('POST');
                url.should.eql('http://my-ghost-auth-server/oauth2/client/redirect');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                JSON.parse(body).client_id.should.eql('123456');
                JSON.parse(body).client_secret.should.eql('secret');

                requestDone(null, JSON.stringify({something: 'test'}));
            });

            return ghostStrategy.changeCallbackURL({
                callbackURL: 'http://localhost:9000/callback',
                clientId: '123456',
                clientSecret: 'secret'
            }).then(function (response) {
                should.exist(response.something);
            });
        });
    });
})
;