'use strict';

// modules ---------------------------------------------------------------------
var crypto        = require('crypto');
var colors        = require('colors');
var moment        = require('moment');
var jwt           = require('jwt-simple');
var request       = require('request');
var qs            = require('querystring');
var async         = require('async');
var nodemailer    = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var Hashids       = require('hashids');
var multiparty    = require('multiparty');
var uuid          = require('uuid');
var s3            = require('s3');
var AWS           = require('aws-sdk');
var fs            = require('fs');
var User          = require('./models/user.js');
var Poem          = require('./models/poem.js');
var auth          = require('./config/auth');

// Pass unique salt value
var hashids = new Hashids(auth.HASHIDS_SALT);

var s3Client = s3.createClient({
  s3Options: {
    accessKeyId     : auth.amazon_s3.ACCESS_KEY_ID,
    secretAccessKey : auth.amazon_s3.SECRET_ACCESS_KEY
  }
});

AWS.config.update({
  accessKeyId     : auth.amazon_s3.ACCESS_KEY_ID,
  secretAccessKey : auth.amazon_s3.SECRET_ACCESS_KEY
});

// var s3 = new AWS.S3();

// routes ----------------------------------------------------------------------
module.exports = function(app) {

  function encrypt(text) {
    var cipher        = crypto.createCipher(auth.ENCRYPTION_KEY, auth.ENCRYPTION_ALGO);
    var encryptedText = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
    return encryptedText;
  }

  function decrypt(encryptedText) {
    var decipher      = crypto.createDecipher(auth.ENCRYPTION_KEY, auth.ENCRYPTION_ALGO);
    var decryptedText = decipher.update(encryptedText, 'hex', 'utf8') + decipher.final('utf8');
    return decryptedText;
  }

  function createToken(stayLoggedIn, user) {
    var expires, payload;

    if (stayLoggedIn) {
      expires = moment().add(14, 'days').valueOf();
      console.log('long session token set'.yellow);
    } else {
      expires = moment().add(1, 'hour').valueOf();
      console.log('short session token set'.yellow);
    }
    payload = {
      user  : user,
      'sub' : hashids.encryptHex(user._id), // subject (identifies the principal that is the subject of the JWT)
      // 'iss' : req.hostname, // issuer (specifies entity making the request)
      'iat' : moment().valueOf(), // The iat (issued at) claim identifies the time at which the JWT was issued.
      'exp' : expires // expires (lifetime of token)
    };
    return jwt.encode(payload, auth.TOKEN_SECRET);
  }

  function ensureAuthenticated(req, res, next) {
    var errMsg;

    // Verify token is present in header
    if (!req.headers.authorization) {
      errMsg = 'The user is not authorized to access this resource.';
      console.log(errMsg.red);
      res.status(401).send({
        type    : 'unauthorized',
        message : errMsg
      });
    } else {

      // Verify user exists
      User.findById(hashids.decryptHex(req.params.id), function(err, user) {
        if (err) {
          res.message = 'The user is not authorized to access this resource.';
          return next(err);
        } else if (!user) {
          errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          var token = req.headers.authorization.split(' ')[1];

          try {
            var payload = jwt.decode(token, auth.TOKEN_SECRET);

            // Verify user is token subject
            if (payload.sub !== req.params.id) {
              errMsg = 'The user is not the token subject.';
              console.log(errMsg.red);
              res.status(401).send({
                type    : 'unauthorized',
                message : errMsg
              });
            } else if (payload.exp <= Date.now()) {
              errMsg = 'The user\'s session token has expired.';
              console.log(errMsg.red);
              res.status(498).send({
                type    : 'token_expired',
                message : errMsg
              });
            } else {
              req.user = user;
              next();
            }
          } catch(ex) {
            errMsg = 'Invalid token. Token has been tampered with.';
            console.log(errMsg.red);
            res.status(401).send({
              type    : 'bad_request',
              message : errMsg
            });
          }
        }
      });
    }
  }

  /**
   * Local signup
   */
  app.post('/api/v1/signup',
    function(req, res, next) {
      console.log('\n[POST] /api/v1/signup'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg;

      // Verify displayName isn't taken
      User.findOne({
        'local.displayName' : req.body.displayName
      }, function(err, user) {
        if (err) {
          res.message = 'The user could not be signed up.';
          return next(err);
        } else if (user) {
          errMsg = 'This username is already taken.';
          console.log(errMsg.red);
          res.status(400).send({
            type    : 'bad_request',
            message : errMsg
          });
        } else {

          // Build new user
          var newUser               = new User();
          newUser.local.displayName = req.body.displayName;
          newUser.email             = req.body.email;
          newUser.password          = newUser.generateHash(req.body.password);
          newUser.avatarUrl         = 'http://api.randomuser.me/portraits/lego/1.jpg';

          // Save new user to the database
          newUser.save(function(err) {
            if (err) {
              res.message = 'The user could not be saved to the database.';
              return next(err);
            } else {
              newUser = newUser.toObject();
              delete newUser.password;
              var token = createToken(req.body.stayLoggedIn, newUser);
              res.status(201).send({
                id    : hashids.encryptHex(newUser._id),
                token : token
              });
            }
          });
        }
      });
    }
  );

  /**
   * Local login
   */
  app.post('/api/v1/login',
    function(req, res, next) {
      console.log('\n[POST] /api/v1/login'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg;

      // http://devsmash.com/blog/implementing-max-login-attempts-with-mongoose
      User.getAuthenticated(req.body.displayName, req.body.password,
        function(err, user, reason) {
          if (err) {
            res.message = 'The user could not be logged in.';
            return next(err);
          } else if (user) {
            console.log('login successful'.green);
            user = user.toObject();
            delete user.password;
            var token = createToken(req.body.stayLoggedIn, user);
            res.status(201).send({
              id    : hashids.encryptHex(user._id),
              token : token
            });
          } else {

            // otherwise we can determine why we failed
            var reasons = User.failedLogin;
            switch (reason) {
              case reasons.NOT_FOUND:
                errMsg = 'The user does not exist.';
                console.log(errMsg.red);
                res.status(404).send({
                  type    : 'not_found',
                  message : errMsg
                });
                break;
              case reasons.PASSWORD_INCORRECT:
                errMsg = 'Wrong username and/or password.';
                console.log(errMsg.red);
                res.status(400).send({
                  type    : 'bad_request',
                  message : errMsg
                });
                break;
              case reasons.MAX_ATTEMPTS:
                errMsg = 'Maximum failed login attempts reached. Please try again later.';
                console.log(errMsg.red);
                res.status(403).send({
                  type    : 'forbidden',
                  message : errMsg
                });
                break;
            }
          }
        }
      );
    }
  );

  /**
   * Forgot password
   */
  app.post('/api/v1/forgot',
    function(req, res, next) {
      console.log('\n[POST] /api/v1/forgot'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;

      async.waterfall([
        function(done) {
          crypto.randomBytes(20, function(err, buf) {
            var token = buf.toString('hex');
            done(err, token);
          });
        },
        function(token, done) {
          // Users with linked accounts will not have local credentials so catch
          // requests with no email specified in the body
          if (!req.body.email) {
            errMsg = 'No account with that email address exists.';
            console.log(errMsg.red);
            res.status(404).send({
              type    : 'not_found',
              message : errMsg
            });
          } else {
            User.findOne({ 'email': req.body.email }, function(err, user) {
              if (!user) {
                errMsg = 'No account with that email address exists.';
                console.log(errMsg.red);
                res.status(404).send({
                  type    : 'not_found',
                  message : errMsg
                });
              } else {
                user.resetPasswordToken   = token;
                user.resetPasswordExpires = moment().add(1, 'hour').valueOf();
                user.save(function(err) {
                  done(err, token, user);
                });
              }
            });
          }
        },
        function(token, user, done) {
          var transport = nodemailer.createTransport(smtpTransport({
            service : 'Mailgun',
            auth : {
              user : 'postmaster@sandbox017bdf6980a2439e84e9151f74a4a3f1.mailgun.org',
              pass : 'Ln9v7MJr7G'
            }
          }));
          var clientHost = 'localhost:9000';
          var redirectLink = 'http://' + clientHost + '/#/reset?token=' + token;
          console.log(redirectLink);
          var mailOptions = {
            to      : user.email,
            from    : 'Mailgun Sandbox <postmaster@sandbox017bdf6980a2439e84e9151f74a4a3f1.mailgun.org>',
            subject : 'Password Reset',
            text    : 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
              'Please click on the following link, or paste this into your browser to complete the process:\n\n' + redirectLink + '\n\n' +
              'If you did not request this, please ignore this email and your password will remain unchanged.\n'
          };
          transport.sendMail(mailOptions, function(err) {
            if (err) {
              res.message = 'Could not send email to reset password.';
              return next(err);
            } else {
              done(err, user);
            }
          });
        }
      ], function(err, user) {
        if (err) {
          res.message = 'Could not send email to reset password.';
          return next(err);
        } else {
          var sucMsg = 'An email has been sent to ' + user.email + ' with further instructions.';
          console.log(sucMsg.green);
          res.status(200).send({
            type    : 'success',
            message : sucMsg
          });
        }
      });
    });

  app.get('/api/v1/reset/:token',
    function(req, res, next) {
      console.log('\n[GET] /api/v1/reset/:token'.bold.green);
      console.log('Request body:'.green, req.body);

      User.findOne({
        resetPasswordToken   : req.params.token,
        resetPasswordExpires : {
          $gt : moment().valueOf()
        }
      }, function(err, user) {
        if (err) {
          res.message = 'The user could not be verified.';
          return next(err);
        } else if (!user) {
          var errMsg = 'No account with that email address exists.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          var sucMsg = 'The user exists.';
          console.log(sucMsg.green);
          res.status(200).send({
            type    : 'success',
            message : sucMsg
          });
        }
      });
    });

  app.post('/api/v1/reset/:token',
    function(req, res, next) {
      console.log('\n[POST] /api/v1/reset/:token'.bold.green);
      console.log('Request body:'.green, req.body);

      async.waterfall([
        function(done) {
          User.findOne({
            resetPasswordToken   : req.params.token,
            resetPasswordExpires : {
              $gt : moment().valueOf()
            }
          }, function(err, user) {
            if (err) {
              res.message = 'The user could not be verified.';
              return next(err);
            } else if (!user) {
              var errMsg = 'The user account doesn\'t exist.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              user.password             = user.generateHash(req.body.password);
              user.resetPasswordToken   = undefined;
              user.resetPasswordExpires = undefined;

              user.save(function(err) {
                if (err) {
                  res.message = 'The user\'s password could not be updated.';
                  return next(err);
                } else {
                  var sucMsg = 'The user\'s password has been updated successfully.';
                  console.log(sucMsg.green);
                  done(err, user);
                }
              });
            }
          });
        },
        function(user, done) {
          var transport = nodemailer.createTransport(smtpTransport({
            service : 'Mailgun',
            auth : {
              user : 'postmaster@sandbox017bdf6980a2439e84e9151f74a4a3f1.mailgun.org',
              pass : 'Ln9v7MJr7G'
            }
          }));
          var mailOptions = {
            to      : user.email,
            from    : 'Mailgun Sandbox <postmaster@sandbox017bdf6980a2439e84e9151f74a4a3f1.mailgun.org>',
            subject : 'Your password has been changed',
            text    : 'Hello,\n\n' +
              'This is a confirmation that the password for your account has just been changed.\n'
          };
          transport.sendMail(mailOptions, function(err) {
            if (err) {
              res.message = 'Could not send changed password confirmation email.';
              return next(err);
            } else {
              done(err, user);
            }
          });
        }
      ],
      function(err, user) {
        if (err) {
          res.message = 'Could not send changed password confirmation email.';
          return next(err);
        } else {
          var sucMsg = 'A changed password confirmation email has been sent to ' + user.email;
          console.log(sucMsg.green);
          res.status(200).send({
            type    : 'success',
            message : sucMsg
          });
        }
      });
    });

  /**
   * Login with Facebook
   */
  app.post('/auth/facebook',
    function(req, res, next) {
      console.log('\n[POST] /auth/facebook'.bold.green);
      console.log('Request body:'.green, req.body);

      var accessTokenUrl = 'https://graph.facebook.com/oauth/access_token';
      var graphApiUrl    = 'https://graph.facebook.com/me';

      var params = {
        client_id     : req.body.clientId,
        redirect_uri  : req.body.redirectUri,
        client_secret : auth.facebook.CLIENT_SECRET,
        code          : req.body.code
      };

      // Step 1. Exchange authorization code for access token.
      request.get({ url: accessTokenUrl, qs: params }, function(err, response, accessToken) {
        accessToken = qs.parse(accessToken);

        // Step 2. Retrieve profile information about the current user.
        request.get({ url: graphApiUrl, qs: accessToken, json: true }, function(err, response, profile) {

          // Step 3a. If user is already signed in then link accounts.
          if (req.headers.authorization) {
            User.findOne({ 'facebook': profile.id }, function(err, existingUser) {
              if (existingUser) {
                return res.status(409).send({ message: 'There is already a Facebook account that belongs to you' });
              } else {

                var token   = req.headers.authorization.split(' ')[1];
                var payload = jwt.decode(token, auth.TOKEN_SECRET);

                User.findById(hashids.decryptHex(payload.sub), function(err, user) {
                  if (!user) {
                    return res.status(400).send({ message: 'User not found' });
                  } else {
                    user.facebook    = profile.id;
                    user.displayName = user.displayName || profile.name;

                    user.save(function(err) {
                      if (err) {
                        res.message = 'The user could not be saved to the database.';
                        return next(err);
                      } else {
                        var token = createToken(undefined /* stayLoggedIn */, user);
                        res.status(200).send({
                          id          : hashids.encryptHex(user._id),
                          token       : token,
                          displayName : user.displayName
                        });
                      }
                    });
                  }
                });
              }
            });
          } else {
            console.log('PROFILE:', profile);

            // Step 3b. Create a new user account or return an existing one.
            User.findOne({ 'facebook': profile.id }, function(err, existingUser) {
              if (existingUser) {
                console.log('3b existing user');
                var token = createToken(undefined /* stayLoggedIn */, existingUser);
                res.status(200).send({
                  id          : hashids.encryptHex(existingUser._id),
                  token       : token,
                  displayName : existingUser.displayName
                });
              } else {
                console.log('3b new user');
                var newUser         = new User();
                newUser.facebook    = profile.id;
                newUser.displayName = profile.name;
                newUser.avatarUrl   = 'http://api.randomuser.me/portraits/lego/1.jpg';

                newUser.save(function(err) {
                  if (err) {
                    res.message = 'The user could not be saved to the database.';
                    return next(err);
                  } else {
                    var token = createToken(undefined /* stayLoggedIn */, newUser);
                    res.status(201).send({
                      id          : hashids.encryptHex(newUser._id),
                      token       : token,
                      displayName : newUser.displayName
                    });
                  }
                });
              }
            });
          }
        });
      });
    });

  /**
   * Login with Github
   */
  app.post('/auth/github',
    function(req, res, next) {
      console.log('\n[POST] /auth/github'.bold.green);
      console.log('Request body:'.green, req.body);

      var accessTokenUrl = 'https://github.com/login/oauth/access_token';
      var userApiUrl     = 'https://api.github.com/user';

      var params = {
        client_id     : req.body.clientId,
        redirect_uri  : req.body.redirectUri,
        code          : req.body.code,
        client_secret : auth.github.CLIENT_SECRET
      };

      // Step 1. Exchange authorization code for access token.
      request.get({ url: accessTokenUrl, qs: params }, function(err, response, accessToken) {
        accessToken = qs.parse(accessToken);

        var headers = { 'User-Agent': 'warrior-poets' };

        // Step 2. Retrieve profile information about the current user.
        request.get({ url: userApiUrl, qs: accessToken, headers: headers, json: true }, function(err, response, profile) {

          // Step 3a. If user is already signed in then link accounts.
          if (req.headers.authorization) {
            User.findOne({ 'github': profile.id }, function(err, existingUser) {
              if (existingUser) {
                return res.status(409).send({ message: 'There is already a GitHub account that belongs to you' });
              } else {
                var token   = req.headers.authorization.split(' ')[1];
                var payload = jwt.decode(token, auth.TOKEN_SECRET);

                User.findById(hashids.decryptHex(payload.sub), function(err, user) {
                  if (!user) {
                    return res.status(400).send({ message: 'User not found' });
                  } else {
                    user.github      = profile.id;
                    user.displayName = user.displayName || profile.name;

                    user.save(function(err) {
                      if (err) {
                        res.message = 'The user could not be saved to the database.';
                        return next(err);
                      } else {
                        var token = createToken(undefined /* stayLoggedIn */, user);
                        res.status(200).send({
                          id          : hashids.encryptHex(user._id),
                          token       : token,
                          displayName : user.displayName
                        });
                      }
                    });
                  }
                });
              }
            });
          } else {
            console.log('PROFILE:', profile);

            // Step 3b. Create a new user account or return an existing one.
            User.findOne({ 'github': profile.id }, function(err, existingUser) {
              if (existingUser) {
                console.log('3b existing user');
                var token = createToken(undefined /* stayLoggedIn */, existingUser);
                res.status(200).send({
                  id          : hashids.encryptHex(existingUser._id),
                  token       : token,
                  displayName : existingUser.displayName
                });
              } else {
                console.log('3b new user');
                var newUser             = new User();
                newUser.github          = profile.id;
                newUser.displayName     = profile.name;
                newUser.avatarUrl = 'https://avatars.githubusercontent.com/u/1514352?v=2';

                newUser.save(function(err) {
                  if (err) {
                    res.message = 'The user could not be saved to the database.';
                    return next(err);
                  } else {
                    var token = createToken(undefined /* stayLoggedIn */, newUser);
                    res.status(201).send({
                      id          : hashids.encryptHex(newUser._id),
                      token       : token,
                      displayName : newUser.displayName
                    });
                  }
                });
              }
            });
          }
        });
      });
    });

  /**
   * Login with Google
   */
  app.post('/auth/google',
    function(req, res, next) {
      console.log('\n[POST] /auth/google'.bold.green);
      console.log('Request body:'.green, req.body);

      var accessTokenUrl = 'https://accounts.google.com/o/oauth2/token';
      var peopleApiUrl   = 'https://www.googleapis.com/plus/v1/people/me/openIdConnect';

      var params = {
        client_id     : req.body.clientId,
        redirect_uri  : req.body.redirectUri,
        client_secret : auth.google.CLIENT_SECRET,
        code          : req.body.code,
        grant_type    : 'authorization_code'
      };

      // Step 1. Exchange authorization code for access token.
      request.post(accessTokenUrl, { json: true, form: params }, function(err, response, token) {

        var accessToken = token.access_token;
        var headers = { Authorization: 'Bearer ' + accessToken };

        // Step 2. Retrieve profile information about the current user.
        request.get({ url: peopleApiUrl, headers: headers, json: true }, function(err, response, profile) {

          // Step 3a. If user is already signed in then link accounts.
          if (req.headers.authorization) {
            User.findOne({ 'google': profile.sub }, function(err, existingUser) {
              if (existingUser) {
                return res.status(409).send({ message: 'There is already a Google account that belongs to you' });
              } else {
                var token = req.headers.authorization.split(' ')[1];
                var payload = jwt.decode(token, auth.TOKEN_SECRET);

                User.findById(hashids.decryptHex(payload.sub), function(err, user) {
                  if (!user) {
                    return res.status(400).send({ message: 'User not found' });
                  }
                  user.google      = profile.sub;;
                  user.displayName = user.displayName || profile.name;

                  user.save(function(err) {
                    if (err) {
                      res.message = 'The user could not be saved to the database.';
                      return next(err);
                    } else {
                      var token = createToken(undefined /* stayLoggedIn */, user);
                      res.status(200).send({
                        id          : hashids.encryptHex(user._id),
                        token       : token,
                        displayName : user.displayName
                      });
                    }
                  });
                });
              }
            });
          } else {
            console.log('PROFILE:', profile);

            // Step 3b. Create a new user account or return an existing one.
            User.findOne({ 'google': profile.sub }, function(err, existingUser) {
              if (existingUser) {
                console.log('3b existingUser');
                var token = createToken(undefined /* stayLoggedIn */, existingUser);
                res.status(200).send({
                  id          : hashids.encryptHex(existingUser._id),
                  token       : token,
                  displayName : existingUser.displayName
                });
              } else {
                console.log('3b new user');
                var newUser         = new User();
                newUser.google      = profile.sub;
                newUser.displayName = profile.name;

                // Google returns profile picture as .../photo.jpg?sz=50
                // So we'll cut the chars from the ? on to have access to the
                // full size image
                var avatar        = profile.picture;
                var charToRemove  = avatar.indexOf('?');
                avatar            = avatar.substring(0, charToRemove = -1 ? charToRemove : avatar.length);
                newUser.avatarUrl = avatar;

                newUser.save(function(err) {
                  if (err) {
                    res.message = 'The user could not be saved to the database.';
                    return next(err);
                  } else {
                    var token = createToken(undefined /* stayLoggedIn */, newUser);
                    res.status(201).send({
                      id          : hashids.encryptHex(newUser._id),
                      token       : token,
                      displayName : newUser.displayName
                    });
                  }
                });
              }
            });
          }
        });
      });
    });

  /**
   * Get a user
   */
  app.get('/api/v1/user/:id',
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      User.findById(hashids.decryptHex(req.params.id), function(err, user) {
        if (err) {
          res.message = 'The user could not be found.';
          return next(err);
        } else if (!user) {
          var errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          res.status(200).send({
            id          : hashids.encryptHex(user._id),
            displayName : user.local.displayName || user.displayName,
            joinedDate  : user.createdAt,
            email       : user.email, // privacy (don't display to others) need to return only when called by logged-in user
            avatarUrl   : user.avatarUrl
          });
        }
      });
    }
  );

  /**
   * Update a user
   */
  app.put('/api/v1/user/:id',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[PUT] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      // req.user retrieved from ensureAuthenticated() middleware
      // res.status(200).send({ message : 'TEST' });
      User.findById(req.user._id, function(err, user) {
        if (err) {
          res.message = 'The user could not be found.';
          return next(err);
        } else if (!user) {
          var errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          user.email = req.body.email || user.email;
          user.save(function(err) {
            if (err) {
              res.message = 'The user could not be saved to the database.';
              return next(err);
            } else {
              var sucMsg = 'The user was updated.';
              var resObj = {};
              resObj.user = user;
              resObj.type = 'success';
              resObj.message = sucMsg;
              console.log(sucMsg.blue);
              res.status(200).send(
                // type    : 'success',
                // message : sucMsg
                resObj
              );
            }
          });
        }
      });
    }
  );

  /**
   * Delete a user
   */
  app.delete('/api/v1/user/:id',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[DELETE] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;

      User.findByIdAndRemove(hashids.decryptHex(req.params.id), function(err, user) {
        if (err) {
          res.message = 'The user could not be deleted.';
          return next(err);
        } else if (!user) {
          errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          sucMsg = 'The user was deleted.';
          console.log(sucMsg.blue);
          res.status(200).send({
            type    : 'success',
            message : sucMsg
          });
        }
      });
    }
  );

  /**
   * Get all users
   */
  app.get('/api/v1/user',
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg;

      User.find(function(err, users) {
        if (err) {
          res.message = 'Could not retrieve all users.';
          return next(err);
        }
        if (!users) {
          errMsg = 'All users could not be found';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        }
        res.status(200).send(users);
      });
    }
  );

  /**
   * Save a new poem to the database
   */
  app.post('/api/v1/user/:id/poem',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user/:id/poem'.bold.green);
      console.log('Request body:'.green, req.body);

      var sucMsg;

      var newPoem = new Poem({
        creator : req.user._id,
        title   : req.body.title,
        poem    : req.body.poem
      });

      newPoem.save(function(err, poem) {
        if (err) {
          res.message = 'Could not save new poem.';
          return next(err);
        } else {
          User.findById(req.user._id, function(err, user) {
            if (err) {
              res.message = 'The user could not be found.';
              return next(err);
            } else if (!user) {
              var errMsg = 'The user could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              user.poems.addToSet(poem._id); // add poem ref to creator

              user.save(function(err) {
                if (err) {
                  res.message = 'Could not save poem ref to user.';
                  return next(err);
                } else {
                  var sucMsg = 'The poem was saved.';
                  console.log(sucMsg.blue);
                  res.status(200).send({
                    type    : 'success',
                    message : sucMsg
                  });
                }
              });
            }
          });
        }
      });
    }
  );

  /**
   * Pull down profile image from temporary S3 bucket, process, and then upload
   * to permanent S3 bucket
   * http://www.cheynewallace.com/uploading-to-s3-with-angularjs/
   */
  app.post('/api/v1/user/:id/profile/image',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:id/profile/image'.bold.green);
      console.log('Request body:'.green, req.body);

      var fileName = req.body.fileName;
      var errMsg, sucMsg;

      async.waterfall([
        function(done) {

          // Download image from temp bucket
          var localPath = './' + fileName;

          var params = {
            localFile: localPath,
            s3Params: {
              Bucket: auth.amazon_s3.BUCKET_TEMPORARY,
              Key: fileName
            }
          };

          var downloader = s3Client.downloadFile(params);

          downloader.on('error', function(err) {
            console.log('Unable to download from temp bucket:', err.stack);
          });

          downloader.on('end', function() {
            sucMsg = 'Successful download from temp bucket';
            console.log(sucMsg.blue);
            done(null, localPath);
          });
        },
        // PROCESS IMAGE
        function(localPath, done) {

          // Upload image to permanent bucket
          var destPath = hashids.encryptHex(req.user._id) + '/profile' + '/' + fileName;

          var params = {
            localFile: localPath,
            s3Params: {
              Bucket: auth.amazon_s3.BUCKET_PERMANENT,
              Key: destPath
            }
          };
          var uploader = s3Client.uploadFile(params);

          uploader.on('error', function(err) {
            console.log('Unable to upload to permanent bucket:', err.stack);
          });

          uploader.on('end', function() {
            sucMsg = 'Successful upload to permanent bucket';
            console.log(sucMsg.blue);

            // delete temp file
            fs.unlink(localPath, function(err) {
              if (err) {
                console.log('Unable to delete temp file:', err.stack);
              } else {
                sucMsg = 'Successful deletion of temporary file';
                console.log(sucMsg.blue);
              }
            });
            done(null, destPath);
          });
        },
        function(destPath, done) {
          var avatarUrl = s3.getPublicUrlHttp(auth.amazon_s3.BUCKET_PERMANENT, destPath);

          // save url to db
          User.findById(req.user._id, function(err, user) {
            if (err) {
              res.message = 'The user could not be found.';
              return next(err);
            } else if (!user) {
              var errMsg = 'The user could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              user.avatarUrl = avatarUrl || user.avatarUrl;
              user.save(function(err) {
                if (err) {
                  res.message = 'The user could not be saved to the database.';
                  return next(err);
                } else {
                  done(null, avatarUrl);
                }
              });
            }
          });
        }
      ], function(err, avatarUrl) {
          console.log('Image found at:', avatarUrl);
          res.status(200).send({
            type            : 'success',
            avatarUrl : avatarUrl
          });
      });
    }
  );

  /**
   * Upload image for user profile
   */
  app.post('/api/v1/user/:id/upload/image',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:id/upload/image'.bold.green);
      console.log('Request body:'.green, req.body);

      var form = new multiparty.Form();
      form.parse(req, function(err, fields, files) {
        var file        = files.file[0];
        console.log(file);
        console.log(file.type);
        var contentType = file.headers['content-type'];
        var extension   = file.path.substring(file.path.lastIndexOf('.'));
        var destPath    = '/' + req.user._id + '/profile' + '/' + uuid.v4() + extension;

        // server side file type checker
        if (contentType !== 'image/png' && contentType !== 'image/jpeg') {
          errMsg = 'Unsupported file type for image upload.';
          console.log(errMsg.red);
          fs.unlink(tmpPath);
          res.status(400).send({
            type    : 'bad_request',
            message : errMsg
          });
        }

        var params = {
          localFile: file.path,
          s3Params: {
            Bucket: auth.amazon_s3.BUCKET_NAME_PERMANENT,
            Key: destPath
          }
        };

        var uploader = s3Client.uploadFile(params);

        uploader.on('error', function(err) {
          console.log('Error: ' + err);
        });

        uploader.on('end', function() {
          console.log('Successful upload');
        });

        // var s3Bucket = new AWS.S3({
        //   params: {
        //     Bucket: auth.amazon_s3.BUCKET_NAME_PERMANENT
        //   }
        // });

        // var data = { Key: destPath, Body: file };

        // s3Bucket.putObject(data, function(err, data) {
        //   if (err) {
        //     console.log('error upload data:', data);
        //     console.log(err);
        //   } else {
        //     console.log('Uploaded file');
        //   }
        // });

        // s3.putObject({
        //   Bucket : auth.amazon_s3.BUCKET_NAME_PERMANENT,
        //   Key    : destPath,
        //   Body   : file
        // }, function(err, data) {
        //   if (err) {
        //     console.log('error upload data:', data);
        //     console.log(err);
        //   } else {
        //     console.log('Uploaded file');
        //   }
        // });

      });
    }
  );

};

// s3.putObject({
//   Bucket : auth.amazon_s3.BUCKET_PERMANENT,
//   Key    : destPath,
//   Body   : localPath
// }, function(err, data) {
//   if (err) {
//     console.log('error upload data:', data);
//     console.log(err);
//   } else {
//     console.log('Uploaded file');
//   }
// });