var oauth2 = require('../lib/oauth2'),
    errors = require('ghost-ignition').errors;

describe('Ghost Oauth2', function () {
    describe('instantiate', function () {
        it('no verify callback', function () {
            try {
                var ghostStrategy = new oauth2.Strategy();
            } catch (err) {
                should.exist(err);
                (err instanceof TypeError).should.eql(true);
            }
        });

        it('with callback url', function () {
            var ghostStrategy = new oauth2.Strategy({
                callbackURL: 'http://localhost:8888/callback',
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
    });
});