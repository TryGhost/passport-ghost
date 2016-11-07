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
  callbackURL: 'your-callback-url',
  blogUri: 'your-blog-url',
  url: 'your-own-auth-server-url',
  passReqToCallback: true
}, callback);

ghostStrategy.registerClient({name: 'your-client-name'});
```