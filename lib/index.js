var jwt = require('jsonwebtoken');
var UnauthorizedError = require('./errors/UnauthorizedError');
var unless = require('express-unless');

module.exports = function(options) {
  if (!options || !options.secret) throw new Error('secret should be set');
  var secure = !!options.secure;
  if (!secure && process.env.NODE_ENV !== 'development') {
    console.log("WARN: express-jwt-cookie will set unsecure cookies; pass {secure: true} to enable secure cookies (if https is available)");
  }

  var middleware = function(req, res, next) {
    var token;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
                                    .split(',').map(function (header) {
                                      return header.trim();
                                    }).indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (typeof options.skip !== 'undefined') {
      console.warn('WARN: express-jwt: options.skip is deprecated');
      console.warn('WARN: use app.use(jwt(options).unless({path: \'/x\'}))');
      if (options.skip.indexOf(req.url) > -1) {
        return next();
      }
    }

    var cookies = secure ? req.signedCookies : req.cookies;
    var COOKIE_NAME = 'jwtuser';

    res.setUser = function(data, jwtConfig){
        res.cookie(COOKIE_NAME, jwt.sign(data, secret, jwtConfig || {}));
    };

    res.unsetUser = function(){
        res.clearCookie(COOKIE_NAME);
    };

    if (!req.cookies) {
        throw new Error("FATAL: express-jwt-cookie requires " + (secure ? "req.signedCookies" : "req.cookies") + " to be set (include cookieParser middleware)");
    } else if (cookies[COOKIE_NAME]) {
      var token = cookies[COOKIE_NAME];
    } else {
      return next();
    }

    jwt.verify(token, options.secret, options, function(err, decoded) {
      if (err) return next(new UnauthorizedError('invalid_token', err));

      req.user = decoded;
      next();
    });
  };

  middleware.unless = unless;

  return middleware;
};
