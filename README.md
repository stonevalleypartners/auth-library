# auth-library
Node Authentication Library

This library handles authentication for REST APIs. The intention is that the APIs are
protected via bearer authentication (all authenticated APIs must use HTTPS; so that the tokens
are not snooped in transit). It supports the login of users via Logins that can be extended
to support additional methods not covered by the library. It currently supports username/password,
google methods and facebook will be added soon.

One of the design goals of this library is to simplify the routing and handling of authentication
while leaving the management of users as the responsbility of the application that leverages
this library.

This works with express.

## Install

```
$ npm install --save git+https://github.com/stonevalleypartners/auth-library.git
```

## Example

Adding support for local user login + bearer tokens requires the following code.

```
var AuthLib = require('auth-library');
// app is an express app that has already been configured with
// a minimum of bodyParser (urlencoded + json)
var auth = new AuthLib.Auth(opts); // see usage below for Auth options
new AuthLib.Logins.Local('local', auth);
auth.initExpress(app);
```

## Usage

### AuthLib.Auth.constructor(options)

Constructs a new auth library instance. The options include required parameters that
allow the library to lookup users, update changes from social logins, handle refresh
tokens, etc.

`options`:

* `lookupAccount`: a function that returns a `User` object; takes an object argument with a single
  property set used to lookup accounts. The property will be one of: `email` or `id`
  for username/password logins.
* `registerExternalAccount`: this function will be called the first time a user
  logs in with a social login to create a new user.
* `tokenDuration`: integer defining how long the bearer tokens should last before expiry
  in seconds; by default this is 3600.
* `refreshDuration`: integer defining how long the refresh tokens should last before
  expiring (a new login will be required once the refresh tokens expire); by default this
  is zero, which means no expiration applies.
* `maxRefreshTokens`: number of refresh tokens to allow a client to use concurrently
  (typically a user will be using one refresh token for each unique browser or app
  they use to access the service). Default is 5; setting this to 0 will disallow
  returning refresh tokens to clients.
* `getExtendedJWTFields`: an optional function that can provide additional fields to
  include in the JWT access token (will be included in both access & refresh tokens)

### Auth.initExpress(app)

Sets up auth related routes for logging in via the configured `Login`s. `app` is an express app.

### Auth.addAuthMiddleware()

This function is the middleware that configures bearer authentication. Use this for all
routes that should b authenticated. Optimally use a router(s) for all routes that require
authentication.

Example:

```
var router = express.Router();
router.use(auth.addAuthMiddleware());

app.use('/api', router);
```

### Auth.encryptObject(obj)

Helper function used to encrypt an object. This is provided as a helper to make it
easy to support features such as verifying an email address, or sending an email
to reset a password.

### Auth.decryptObject(string)

Helper function used to decrypt a string. This is provided as a helper to make it
easy to support features such as verifying an email address, or sending an email
to reset a password.

## User

The `User` object is an abstract data type and should be subclassed by an application.
The intention is that the application manages most of the user information; but
authentication needs some control to update information (coming from social applications)
manage passwords (passwords must never be stored in a raw form... otherwise an attack
from the server might expose passwords which is a very serious breach to the server),
find the user records for logins, and update refresh tokens used by a user.

### AuthLib.User.constructor()

Constructs a new user object. This will include `auth` and `social` properties that are
managed by the AuthLib library. All other parameters are the responsibliity of the
application. It is important for the application to handle refresh tokens.

Example:
```
class MyUser extends AuthLib.User {
  constructor(name) {
    super();
    this.name = name;
  }
}

var myuser = new MyUser('Jane Doe');
```

### user.setPassword(pw)

Use this function to set a password for the user. Do not set a property in the user class
for the password; this will be handled by this function. This will store a hashed
version of the password within the `auth` property of the `User`.

Example:
```
myuser.setPassword('secret');
```

### user.save()

Define a function in the subclass extending `User` to save the user (e.g. to mongodb). This
function should return a promise that resolves when the user has been saved.

### user.toJSON()

Used as part of stringifying a user. This removes the `auth` property on the user; which means
that the serialized string can be sent to clients of the API. This should not be used before
storing users in a database though.

Example:
```
console.log(JSON.stringify(myuser)
// results in {"social": {}, name: "Jane Doe"}
```

### user.checkRefreshToken(token)

This function must be impleted by the user object and is responsible for checking whether
a refreshToken is associated with this object. Refresh tokens allow login access for the
user and should be managed by the application (e.g. applications likely need to provide
an API that allows users to logout and/or revoke access from particular devices). This
function will be called for the particular user with the token value that is being
provided for authentication. The application should determine if this is valid. Returns a
promise that resolves to true (valid refresh token) or false (invalid).
