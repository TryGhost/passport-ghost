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

        it('with redirect uri', function () {
            var ghostStrategy = new oauth2.Strategy({
                redirectUri: 'http://localhost:8888/callback',
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
                redirectUri: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });

            should.exist(ghostStrategy);
            ghostStrategy.url.should.eql('http://my-ghost-auth-server');
        });
    });

    describe('meta tests', function () {
        it('service is down', function (done) {
            var ghostStrategy = new oauth2.Strategy({
                redirectUri: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://localhost:8081',
                retryTimeout: 100
            }, function verifyCallback() {
            });

            sandbox.spy(ghostStrategy, 'makeRequest');

            ghostStrategy.registerClient({name: 'my-client'})
                .then(function () {
                    done(new Error('expected error'));
                })
                .catch(function (err) {
                    err.code.should.eql('ECONNREFUSED');
                    ghostStrategy.makeRequest.callCount.should.eql(11);
                    done();
                });
        });
    });

    describe('get user profile by token', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                redirectUri: 'http://localhost:8888/callback',
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
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, token, profileDone) {
                profileDone(null, 'body');
            });

            ghostStrategy.userProfile('access-token', function (err) {
                should.exist(err);
                done();
            });
        });

        it('with access token', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, token, profileDone) {
                token.should.eql('access-token');
                url.should.eql('http://my-ghost-auth-server/oauth2/userinfo/');
                profileDone(null, JSON.stringify({profile: 'katharina'}));
            });

            ghostStrategy.userProfile('access-token', function (err, response) {
                should.not.exist(err);
                should.exist(response.profile);
                done();
            });
        });
    });

    describe('get user profile by identity id', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                redirectUri: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('no id', function (done) {
            ghostStrategy.userProfileByIdentityId(null, function (err) {
                should.exist(err);
                done();
            });
        });

        it('with id: cant parse body', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, token, profileDone) {
                profileDone(null, 'body');
            });

            ghostStrategy.userProfileByIdentityId('1234', function (err) {
                should.exist(err);
                done();
            });
        });

        it('with id and success', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, token, profileDone) {
                should.not.exist(token);
                url.should.eql('http://my-ghost-auth-server/oauth2/userinfo/1234/?client_id=clientID&client_secret=clientSecret');
                profileDone(null, JSON.stringify({profile: 'katharina'}));
            });

            ghostStrategy.userProfileByIdentityId('1234', function (err, response) {
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
                redirectUri: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('error', function () {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('POST');
                url.should.eql('http://my-ghost-auth-server/oauth2/client/');
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
                url.should.eql('http://my-ghost-auth-server/oauth2/client/');
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
                redirectUri: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('error: no data send ', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/password/');
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
                    (err instanceof errors.ValidationError).should.eql(true);
                    done();
                });
        });

        it('error: no data send (JSONAPI FORMAT)', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/password/');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                should.not.exist(JSON.parse(body).access_token);
                should.not.exist(JSON.parse(body).oldPassword);

                requestDone({
                    statusCode: 422,
                    data: JSON.stringify(errors.utils.serialize(new errors.ValidationError({
                        message: 'validation error'
                    }), {format: 'oauth'}))
                });
            });

            ghostStrategy.changePassword(null)
                .catch(function (err) {
                    should.exist(err);
                    (err instanceof errors.IgnitionError).should.eql(true);
                    (err instanceof errors.ValidationError).should.eql(true);
                    done();
                });
        });

        it('success', function (done) {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/password/');
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

    describe('update client', function () {
        var ghostStrategy;

        before(function () {
            ghostStrategy = new oauth2.Strategy({
                redirectUri: 'http://localhost:8888/callback',
                blogUri: 'http://example.com',
                passReqToCallback: true,
                url: 'http://my-ghost-auth-server'
            }, function verifyCallback() {
            });
        });

        it('success', function () {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/client/');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                JSON.parse(body).client_id.should.eql('123456');
                JSON.parse(body).client_secret.should.eql('secret');
                JSON.parse(body).name.should.eql('my-client');
                should.not.exist(JSON.parse(body).description);

                requestDone(null, JSON.stringify({something: 'test'}));
            });

            return ghostStrategy.updateClient({
                clientId: '123456',
                clientSecret: 'secret',
                name: 'my-client'
            }).then(function (response) {
                should.exist(response.something);
            });
        });

        it('success', function () {
            sandbox.stub(ghostStrategy._oauth2, '_request', function (method, url, headers, body, query, requestDone) {
                method.should.eql('PUT');
                url.should.eql('http://my-ghost-auth-server/oauth2/client/');
                headers['content-type'].should.eql('application/json');
                (typeof body).should.eql('string');
                JSON.parse(body).client_id.should.eql('123456');
                JSON.parse(body).client_secret.should.eql('secret');
                JSON.parse(body).name.should.eql('my-client');
                JSON.parse(body).description.should.eql('description');
                JSON.parse(body).blog_uri.should.eql('http://has-changed');
                should.not.exist(JSON.parse(body).redirect_uri);

                requestDone(null, JSON.stringify({something: 'test'}));
            });

            return ghostStrategy.updateClient({
                clientId: '123456',
                clientSecret: 'secret',
                name: 'my-client',
                description: 'description',
                blogUri: 'http://has-changed'
            }).then(function (response) {
                should.exist(response.something);
            });
        });
    });
});