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
  redirectUri: 'your-redirect-url',          [required]
  blogUri: 'your-blog-url',                  [required]
  url: 'your-own-auth-server-url',           [required]
  passReqToCallback: true                    [optional]
  retries                                    [optional] default 10
  retryTimeout                               [optional] default 5000ms
  retryHook: function                        [optional] If an error occurs while retrying, you can define a hook to get notified
}, callback);

ghostStrategy.registerClient({
  name: 'your-client-name',                  [required]
  description: 'your blog description'       [optional]
});

ghostStrategy.updateClient({
  clientId: 'your-client-id',                [required]
  clientSecret: 'your-client-secret',        [required]
  name: 'your-client-name',                  [optional]
  description: 'your blog description',      [optional]
  redirectUri: 'your-redirect-url',          [optional]
  blogUri: 'your-blog-url'                   [optional]
});
```

# Copyright & License

Copyright (c) 2016-2017 Ghost Foundation - Released under the [MIT license](LICENSE).
