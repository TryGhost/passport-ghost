# passport-ghost
Passport adapter for logging in with Ghost.org


## install
```
npm install passport-ghost
```

## usage

```
var GhostStrategy = require('passport-ghost').Strategy;

var ghostStrategy = new GhostStrategy({
  callbackURL: 'your-callback-url',          [required]
  blogUri: 'your-blog-url',                  [required]
  url: 'your-own-auth-server-url',           [required]
  passReqToCallback: true                    [optional]
}, callback);

ghostStrategy.registerClient({
  name: 'your-client-name',                  [required]
  description: 'your blog description'       [optional]
});
```