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
var fs            = require('fs');
var PDFDocument   = require('pdfkit');
var User          = require('./models/user.js');
var Poem          = require('./models/poem.js');
var Comment       = require('./models/comment.js');
var auth          = require('./config/auth.js');

var hashids = new Hashids(auth.HASHIDS_SALT);

var pdfStream = new PDFDocument;

var s3Client = s3.createClient({
  s3Options: {
    accessKeyId     : auth.amazon_s3.ACCESS_KEY_ID,
    secretAccessKey : auth.amazon_s3.SECRET_ACCESS_KEY
  }
});

// routes ----------------------------------------------------------------------
module.exports = function(app, io, clientSocketsHash, loggedInClientsHash) {

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

  // Function for sorting by creation date
  function compareTimestampsAsc(a, b) {
    if (a.createdAt < b.createdAt)
      return 1;
    if (a.createdAt > b.createdAt)
      return -1;
    return 0;
  }

  function compareTimestampsDesc(a, b) {
    if (a.createdAt < b.createdAt)
      return -1;
    if (a.createdAt > b.createdAt)
      return 1;
    return 0;
  }

  function extractDomain(url) {
    return url.split('/')[2] || url.split('/')[0];
  }

  function youtubeIdParser(url) {
    var regExp = /.*(?:youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=)([^#\&\?]*).*/;
    var match = url.match(regExp);
    if (match && match[1].length == 11){
        return match[1];
    } else {
      console.log('error parsing YouTube url');
      return 1;
    }
  }

  function vimeoIdParser(url) {
    // look for a string with 'vimeo', then whatever, then a forward slash, and a group of digits.
    var match = /vimeo.*\/(\d+)/i.exec(url);
    if (match) {
      return match[1];
    } else {
      return 1;
    }
  }

  function startSocketSession(req, userId) {
    if (req.headers.socketid) {
      console.log('(startSocketSession) logging in client:', userId);
      loggedInClientsHash[userId] = req.headers.socketid;
      console.log('(startSocketSession) total logged in clients:', Object.keys(loggedInClientsHash));
      console.log('(startSocketSession) total connected clients:', Object.keys(clientSocketsHash));
    } else {
      console.log('(startSocketSession) no socket id found in request header.');
    }
  }

  function endSocketSession(req, userId) {
    if (req.headers.socketid) {
      console.log('(endSocketSession) logging out client:', userId);
      delete loggedInClientsHash[userId];
      console.log('(endSocketSession) total logged in clients:', Object.keys(loggedInClientsHash));
      console.log('(endSocketSession) total connected clients:', Object.keys(clientSocketsHash));
    }
  }

  function createToken(stayLoggedIn, user, req) {
    var expires, payload;

    if (stayLoggedIn) {
      expires = moment().add(14, 'days').valueOf();
      console.log('long session token set'.yellow);
    } else {
      expires = moment().add(1, 'day').valueOf();
      console.log('short session token set'.yellow);
    }
    payload = {
      user  : user,
      'sub' : hashids.encryptHex(user._id), // subject (identifies the principal that is the subject of the JWT)
      'iss' : req.hostname,                 // issuer (specifies entity making the request)
      'iat' : moment().valueOf(),           // The iat (issued at) claim identifies the time at which the JWT was issued.
      'exp' : expires                       // expires (lifetime of token)
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

      var userId = req.params.id || req.params.userId;

      // Verify user exists
      User.findById(hashids.decryptHex(userId), function(err, user) {
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
            if (payload.sub !== userId) {
              errMsg = 'The user is not the token subject.';
              console.log(errMsg.red);
              res.status(401).send({
                type    : 'unauthorized',
                message : errMsg
              });
            } else if (payload.exp <= Date.now()) {
              errMsg = 'The user\'s session token has expired.';
              console.log(errMsg.red);

              endSocketSession(req, hashids.decryptHex(userId));

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
   * Welcome
   */
  app.get('/',
    function(req, res) {
      console.log('\n[GET] /'.bold.green);
      console.log('Request body:'.green, req.body);

      res.status(200).send({
        type    : 'success',
        message : 'Welcome to the Numa API! Have fun.'
      });
    }
  );

  /**
   * Generate PDF of user poems
   */
  app.get('/api/v1/user/:id/poem/pdf',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user/:id/poem/pdf'.bold.green);
      console.log('Request body:'.green, req.body);

      pdfStream.pipe(fs.createWriteStream(__dirname + '/tmp/test.pdf'));
      pdfStream.fontSize(15);
      pdfStream.text('test');
      pdfStream.end();

      var filePath = __dirname + '/tmp/test.pdf';
      var fileName = 'new.pdf';

      res.download(filePath, fileName, function(err) {
        if (err) {
          console.log(err);
          // if (!res.headersSent) ...
        } else {
          console.log('Send:', fileName);
        }
      });
    }
  );

  app.get('/socket/:id',
    function(req, res, next) {
      console.log('\n[GET] /socket/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      console.log('client hash', clientSocketsHash);
      console.log('log clients:', loggedInClientsHash);

      var socket = clientSocketsHash[loggedInClientsHash[req.params.id+'']];
      if (socket !== undefined) {
        console.log('emitting TEST event');
        socket.emit('TEST', { test : 'THIS IS A TEST THINGY' });

        sucMsg = 'The socket should have emitted something';
        res.status(200).send({ message : sucMsg });
      } else {
        errMsg = 'client socket id is undefined';
        console.log(errMsg);
        res.status(400).send({ message : errMsg});
      }
    });


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
              var token = createToken(req.body.stayLoggedIn, newUser, req);

              startSocketSession(req, newUser._id);

              res.status(201).send({
                type  : 'success',
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
            var token = createToken(req.body.stayLoggedIn, user, req);

            startSocketSession(req, user._id);

            res.status(201).send({
              type  : 'success',
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
   * Local logout
   */
  app.get('/api/v1/user/:id/logout',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user/:id/logout'.bold.green);
      console.log('Request body:'.green, req.body);

      var userId = req.params.id;

      endSocketSession(req, hashids.decryptHex(userId));

      res.status(200).send({
        type    : 'success',
        message : 'User logged out.'
      });
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
          var redirectLink = 'http://' + clientHost + '/#!/reset?token=' + token;
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
          var sucMsg = 'A changed password confirmation email has been sent to ' + user.email + '.';
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
                        var token = createToken(true, user, req);

                        startSocketSession(req, user._id);

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
                var token = createToken(true, existingUser, req);

                startSocketSession(req, existingUser._id);

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
                    var token = createToken(true, newUser, req);

                    startSocketSession(req, newUser._id);

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
                        var token = createToken(true, user, req);

                        startSocketSession(req, user._id);

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
                var token = createToken(true, existingUser, req);

                startSocketSession(req, existingUser._id);

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
                    var token = createToken(true, newUser, req);

                    startSocketSession(req, newUser._id);

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
                      var token = createToken(true, user, req);

                      startSocketSession(req, user._id);

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
                var token = createToken(true, existingUser, req);

                startSocketSession(req, existingUser._id);

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
                    var token = createToken(true, newUser, req);

                    startSocketSession(req, newUser._id);

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
   * query:
   *   If req.query.profile === 'full', send full profile
   */
  app.get('/api/v1/user/:id',
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg;
      var userId = hashids.decryptHex(req.params.id);

      User.findById(userId, function(err, user) {
        if (err) {
          res.message = 'The user could not be found.';
          return next(err);
        } else if (!user) {
          errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          var resObj                 = {};
          resObj.id                  = hashids.encryptHex(user._id);
          resObj.displayName         = user.local.displayName || user.displayName;
          resObj.createdAt           = user.createdAt;
          resObj.email               = user.email;
          resObj.avatarUrl           = user.avatarUrl;
          resObj.unreadCommentsCount = user.unreadComments.length || 0;

          if (req.query.profile === 'full') {

            // gather user poem titles and user comments
            var poems = [];

            async.waterfall([
              function(done) {
                async.each(user.poems,
                  function(id, callback) {
                    Poem.findById(id, function(err, poem) {
                      if (poem) {
                        var poemObj       = {};
                        poemObj.id        = hashids.encryptHex(poem._id),
                        poemObj.title     = poem.title;
                        poemObj.poem      = poem.poem;
                        poemObj.createdAt = poem.createdAt;
                        poems.push(poemObj);
                        callback();
                      }
                    });
                  },
                  function(err) {
                    resObj.poems = poems;
                    done(null, resObj);
                  }
                );
              },
              function(resObj, done) {
                var comments = [];
                async.each(user.comments,
                  function(id, callback) {
                    Comment.findById(id).populate('poem').exec(function(err, comment) {
                      if (comment) {
                        var commentObj       = {};
                        commentObj.id        = hashids.encryptHex(comment._id),
                        commentObj.comment   = comment.comment;
                        commentObj.createdAt = comment.createdAt;
                        commentObj.poemId    = hashids.encryptHex(comment.poem._id);
                        commentObj.poemTitle = comment.poem.title;
                        comments.push(commentObj);
                        callback();
                      }
                    });
                  },
                  function(err) {
                    resObj.comments = comments;
                    done(null, resObj);
                  }
                );
              },
              function(resObj, done) {
                var unreadComments = [];
                async.each(user.unreadComments,
                  function(id, callback) {
                    Comment.findById(id).populate('poem').exec(function(err, comment) {
                      if (comment) {
                        var unreadCommentObj       = {};
                        unreadCommentObj.id        = hashids.encryptHex(comment._id),
                        unreadCommentObj.comment   = comment.comment;
                        unreadCommentObj.createdAt = comment.createdAt;
                        unreadCommentObj.poemId    = hashids.encryptHex(comment.poem._id);
                        unreadCommentObj.poemTitle = comment.poem.title;
                        unreadComments.push(unreadCommentObj);
                        callback();
                      }
                    });
                  },
                  function(err) {
                    resObj.unreadComments = unreadComments;
                    done(null, resObj);
                  }
                );
              },
              function(resObj, done) {
                var favoritePoems = [];
                async.each(user.favoritePoems,
                  function(id, callback) {
                    Poem.findById(id, function(err, poem) {
                      if (poem) {
                        var favoritePoemObj       = {};
                        favoritePoemObj.id        = hashids.encryptHex(poem._id),
                        favoritePoemObj.title     = poem.title;
                        favoritePoemObj.poem      = poem.poem;
                        favoritePoemObj.createdAt = poem.createdAt;
                        favoritePoems.push(favoritePoemObj);
                        callback();
                      }
                    });
                  },
                  function(err) {
                    resObj.favoritePoems = favoritePoems;
                    done(null, resObj);
                  }
                );
              },
            ], function(err, resObj) {
              if (err) {
                res.message = 'Could not get user details.';
                return next(err);
              } else {
                resObj.type = 'success';
                res.status(200).send(resObj);
              }
            });
          } else {
            resObj.type = 'success';
            res.status(200).send(resObj);
          }
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
      User.findByIdAndUpdate(req.user._id, {
        'email' : req.body.email || user.email
      }, function(err, user) {
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
          var sucMsg = 'The user was updated.';
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
   * Delete a user
   */
  app.delete('/api/v1/user/:id',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[DELETE] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;

      User.findByIdAndRemove(req.user._id, function(err, user) {
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
   * Get 25 poems per page, paginating by page, sorted in ascending order by creation date
   *
   * http://localhost:3000/api/v1/poem/?query=love&page=1&searchby=poem
   *
   * query    : normal search query (case insensitive)
   * searchby : title, tag, content
   * page     : page number
   */
  app.get('/api/v1/poem',
    function(req, res, next) {
      console.log('\n[GET] /api/v1/poem/'.bold.green);
      console.log('Request body:'.green, req.body);

      var poemQuery, pageNumber, searchBy, errMsg, sucMsg, caseInsensitiveRegex, query = {};

      poemQuery  = req.query.query || null;
      req.query.page > 0 ? pageNumber = req.query.page : pageNumber = 1;

      if (typeof req.query.searchby === 'undefined') {
        searchBy = 'title';
      } else {
        searchBy = req.query.searchby.split(',');
      }

      // find all documents
      if (poemQuery === null) {
        query = {};
      } else {
        caseInsensitiveRegex = { $regex: poemQuery, $options: 'i' };

        // if multiple query strings, AND them together for a query
        if (searchBy instanceof Array && searchBy.length > 1) {
          var field, i;
          if (req.query.strict === 'true') {
            for (i = searchBy.length - 1; i >= 0; i--) {
              field = searchBy[i];
              if (field === 'content') {
                query['poem'] = caseInsensitiveRegex;
              } else if (field === 'tag') {
                query['tags'] = caseInsensitiveRegex;
              } else if (field === 'title') {
                query['title'] = caseInsensitiveRegex;
              }
            };
          } else {
            query['$or'] = [];
            for (i = searchBy.length - 1; i >= 0; i--) {
              field = searchBy[i];
              if (field === 'content') {
                query['$or'].push({ 'poem': caseInsensitiveRegex });
              } else if (field === 'tag') {
                query['$or'].push({ 'tags': caseInsensitiveRegex });
              } else if (field === 'title') {
                query['$or'].push({ 'title': caseInsensitiveRegex });
              }
            };
          }
        } else if (searchBy instanceof Array && searchBy.length === 1) {
          if (searchBy[0] === 'content') {
            query['poem'] = caseInsensitiveRegex;
          } else if (searchBy[0] === 'tag') {
            query['tags'] = caseInsensitiveRegex;
          } else if (searchBy[0] === 'title') {
            query['title'] = caseInsensitiveRegex;
          }
        } else if (typeof searchBy === 'string') {
          if (searchBy === 'content') {
            query['poem'] = caseInsensitiveRegex;
          } else if (searchBy === 'tag') {
            query['tags'] = caseInsensitiveRegex;
          } else if (searchBy === 'title') {
            query['title'] = caseInsensitiveRegex;
          }
        }
      }

      console.log(query);

      async.waterfall([
        function(done) {
          Poem.paginate(query, pageNumber, 8, function(err, pageCount, paginatedPoems, itemCount) {
            if (err) {
              res.message = 'Could not retrieve poems.';
              return next(err);
            } else if (paginatedPoems.length === 0) {
              errMsg = 'No more poems to retrieve';
              console.log(errMsg.red);
              res.status(200).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              done(null, paginatedPoems, pageCount, itemCount);
            }
          }, { sortBy : '-createdAt' });
        }
      ], function(err, paginatedPoems, pageCount, poemCount) {
          // for each poem, get the creator's information
          var resArr = [];
          var creator = {};

          async.each(paginatedPoems,
            function(poem, callback) {
              User.findById(poem.creator, function(err, user) {
                if (user) {
                  creator               = {};
                  creator.id            = hashids.encryptHex(user._id);
                  creator.displayName   = user.displayName || user.local.displayName;
                  poem                  = poem.toObject();
                  poem.id               = hashids.encryptHex(poem._id);
                  poem.creator          = creator;
                  poem.numberOfComments = poem.comments.length;
                  poem.positiveVotes    = poem.vote.positive.length;
                  poem.negativeVotes    = poem.vote.negative.length;

                  delete poem._id;
                  delete poem.__v;
                  delete poem.vote;
                  delete poem.comments;
                  delete poem.vote;

                  resArr.push(poem);
                  callback();
                }
              });
            },
            function(err) {
              // sort poems in ascending order by creation date
              resArr.sort(compareTimestampsAsc);
              res.status(200).send({
                type      : 'success',
                poemCount : poemCount,
                pageCount : pageCount,
                poems     : resArr
              });
            }
          );
        }
      );
    }
  );

  /*
   * Get poem by id
   */
  app.get('/api/v1/poem/:id',
    function(req, res, next) {
      console.log('\n[GET] /api/v1/poem/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      var poemId = hashids.decryptHex(req.params.id);

      async.waterfall([
        function(done) {
          Poem.findById(poemId, function(err, poem) {
            if (!poem) {
              errMsg = 'The poem could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              done(null, poem);
            }
          });
        },
        function(poem, done) {
          User.findById(poem.creator, function(err, user) {
            if (!user) {
              // User could be deleted, handle gracefully
              errMsg = 'The user could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              done(null, user, poem);
            }
          });
        },
        function(user, poem, done) {
          // gather poem comments
          var resObj   = {};
          var comments = [];
          async.each(poem.comments,
            function(id, callback) {
              Comment.findById(id, function(err, comment) {
                if (comment) {
                  var commentObj       = {};
                  commentObj.id        = hashids.encryptHex(comment._id),
                  commentObj.comment   = comment.comment;
                  commentObj.createdAt = comment.createdAt;

                  User.findById(comment.creator, function(err, user) {
                    if (err) {
                      errMsg = 'A comment creator could not be found...';
                      console.log(errMsg.red);
                    } else {
                      var creator         = {};
                      creator.id          = hashids.encryptHex(user._id);
                      creator.displayName = user.displayName || user.local.displayName;
                      creator.avatarUrl   = user.avatarUrl;
                      commentObj.creator  = creator;
                      comments.push(commentObj);
                      callback();
                    }
                  });
                }
              });
            },
            function(err) {
              // Sort comments by createdAt in descending order
              comments.sort(compareTimestampsDesc);

              var creator            = {};
              creator.id             = hashids.encryptHex(user._id);
              creator.displayName    = user.displayName || user.local.displayName;
              creator.avatarUrl      = user.avatarUrl;
              creator.unreadComments = user.unreadComments;
              poem                   = poem.toObject();
              poem.positiveVotes     = poem.vote.positive.length;
              poem.negativeVotes     = poem.vote.negative.length;

              delete poem._id;
              delete poem.__v;
              delete poem.creator;
              delete poem.comments;
              delete poem.vote;

              resObj.poem          = poem;
              resObj.poem.creator  = creator;
              resObj.poem.comments = comments;
              done(null, resObj, user._id);
            }
          );
        },
        function(resObj, creatorId, done) {
          if (!req.headers.authorization) {
            console.log('no token in header');
            done(null, resObj);
          } else {
            var token = req.headers.authorization.split(' ')[1];
            var payload = jwt.decode(token, auth.TOKEN_SECRET);
            if (payload.sub == hashids.encryptHex(creatorId)) {
              console.log('The creator is requesting.');

              // Remove each unreadComment of this poem from creator's unreadComments[]
              var unreadComments = resObj.poem.creator.unreadComments;
              if (unreadComments !== undefined && unreadComments.length > 0) {
                console.log('Unread comments, so removing...', unreadComments);
                async.each(unreadComments,
                  function(commentId, callback) {
                    Comment.findById(commentId).populate('poem').exec(function(err, comment) {
                      if (poemId == comment.poem._id) {
                        User.findByIdAndUpdate(creatorId, {
                          '$pull': {
                            unreadComments: commentId
                          }
                        }, function(err, user) {
                          callback();
                        });
                      }
                    });
                  },
                  function(err) {
                    done(null, resObj);
                  }
                );
              } else {
                console.log('No unread comments');
                done(null, resObj);
              }
            } else {
              console.log('The creator isn\'t requesting.');
              done(null, resObj);
            }
          }

        }
      ], function(err, resObj) {
        if (err) {
          res.message = 'Could not save the poem.';
          return next(err);
        } else {
          resObj.type = 'success';
          res.status(200).send(resObj);
        }
      });
    }
  );

  /**
   * Update a poem
   */
  app.put('/api/v1/user/:userId/poem/:poemId',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[PUT] /api/v1/user/:userId/poem/:poemId'.bold.green);
      console.log('Request body:'.green, req.body);

      // Verify userId matches poem's creator Id

      Poem.findByIdAndUpdate(hashids.decryptHex(req.params.poemId), {
        'title'                    : req.body.title,
        'poem'                     : req.body.poem,
        'tags'                     : req.body.tags || '',
        // 'inspirations.song.artist' : req.body.songArtist || '',
        // 'inspirations.song.title'  : req.body.songTitle || '',
        // 'inspirations.song.url'    : req.body.songUrl || '',
        'inspirations.imageUrl'    : req.body.imageUrl || '',
        'inspirations.videoUrl'    : req.body.videoUrl || ''
      }, function(err, poem) {
        if (err) {
          res.message = 'The poem could not be found.';
          return next(err);
        } else if (!poem) {
          var errMsg = 'The poem could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          var sucMsg = 'The poem was updated.';
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
   * Delete a comment (as creator)
   */
  app.delete('/api/v1/user/:userId/poem/:poemId/comment/:commentId',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[DELETE] /api/v1/user/:userId/poem/:poemId'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      var userId    = hashids.decryptHex(req.params.userId);
      var poemId    = hashids.decryptHex(req.params.poemId);
      var commentId = hashids.decryptHex(req.params.commentId);
      // console.log('userid:', userId);
      // console.log('poemid:', poemId);
      // console.log('commentid:', commentId);

      async.waterfall([
        function(done) {
          Comment.findById(commentId).populate('poem').exec(function(err, comment) {
            if (err) {
              res.message = 'The comment could not be found.';
              return next(err);
            } else if (!comment) {
              errMsg = 'The comment could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else if ((comment.poem.creator == req.user._id + '') || (comment.creator == req.user._id + '')) {
              done(null);
            } else {
              errMsg = 'The requesting user is not the poem\'s creator.';
              console.log(errMsg.red);
              res.status(401).send({
                type    : 'unauthorized',
                message : errMsg
              });
            }
          });
        },
        function(done) {
          // Delete comment
          Comment.findByIdAndRemove(commentId, function(err, comment) {
            if (comment) {
              done(null, comment);
            }
          });
        },
        function(comment, done) {
          // Delete comment ref from user
          User.findByIdAndUpdate(comment.creator, {
            '$pull': {
              comments: comment._id
            }
          }, function(err, user) {
            if (user) {
              done(null, comment, user);
            }
          });
        },
        function(comment, user, done) {
          // Delete comment ref from poem
          Poem.findByIdAndUpdate(comment.poem, {
            '$pull': {
              comments: comment._id
            }
          }, function(err, poem) {
            if (poem) {
              done(null);
            }
          });
        }
      ], function() {
        sucMsg = 'The comment was deleted.';
        console.log(sucMsg.blue);
        res.status(200).send({
          type    : 'success',
          message : sucMsg
        });
      });
    }
  );

  /**
   * Delete inspirational image from poem
   */
  app.delete('/api/v1/user/:userId/poem/:poemId/image',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[DELETE] /api/v1/user/:userId/poem/:poemId/image'.bold.green);
      console.log('Request body:'.green, req.body);

      if (req.body.imageUrl) {
        var remoteImage = req.body.imageUrl.split(".com/").pop();
        var poemId = hashids.decryptHex(req.params.poemId);
        var errMsg, sucMsg;

        var s3Params = {
          Bucket : auth.amazon_s3.BUCKET_PERMANENT,
          Delete : {
            Objects: [{
              Key : remoteImage
            }]
          }
        };

        var deleter = s3Client.deleteObjects(s3Params);

        deleter.on('error', function(err) {
          errMsg = 'Unable to delete image.';
          console.log(errMsg.red);
          res.status(500).send({
            type    : 'internal_server_error',
            message : errMsg
          });
        });

        deleter.on('end', function() {
          sucMsg = 'Successful deletion of image.';
          console.log(sucMsg.blue);

          Poem.findByIdAndUpdate(poemId, {
            '$unset': {
              'inspirations.imageUrl': ""
            }
          }, function(err) {
            if (err) {
              console.log(err);
            } else {
              res.status(200).send({
                type    : 'success',
                message : sucMsg
              });
            }
          });
        });
      } else {
        errMsg = 'Unable to delete image: missing request body.';
        console.log(errMsg.red);
        res.status(400).send({
          type    : 'bad_request',
          message : errMsg
        });
      }
    }
  );


  /**
   * Delete a poem
   */
  app.delete('/api/v1/user/:userId/poem/:poemId',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[DELETE] /api/v1/user/:userId/poem/:poemId'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      var poemId = hashids.decryptHex(req.params.poemId);
      var userId = hashids.decryptHex(req.params.userId);

      async.waterfall([
        function(done) {
          Poem.findById(poemId, function(err, poem) {
            if (err) {
              res.message = 'The poem could not be found.';
              return next(err);
            } else if (!poem) {
              errMsg = 'The poem could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else if (poem.creator == req.user._id + '') {
              done(null);
            } else {
              // userId doesn't match poem's creator id
              // console.log(poem.creator);
              // console.log(req.user._id);
              errMsg = 'The requesting user is not the poem\'s creator.';
              console.log(errMsg.red);
              res.status(401).send({
                type    : 'unauthorized',
                message : errMsg
              });
            }
          });
        },
        function(done) {
          // Delete poem
          Poem.findByIdAndRemove(poemId, function(err, poem) {
            // if (err) {
            //   res.message = 'The poem could not be deleted.';
            //   return next(err);
            // } else if (!poem) {
            //   errMsg = 'The poem could not be found.';
            //   console.log(errMsg.red);
            //   res.status(404).send({
            //     type    : 'not_found',
            //     message : errMsg
            //   });
            // } else {
              done(null, poem);
            // }
          });
        },
        function(poem, done) {
          // Delete poem reference from user
          User.findByIdAndUpdate(poem.creator, {
            '$pull': {
              poems: poem._id
            }
          }, function(err, user) {
            // if (err) {
            //   res.message = 'The user could not be found and updated.';
            //   return next(err);
            // } else if (!user) {
            //   var errMsg = 'The user could not be found and updated.';
            //   console.log(errMsg.red);
            //   res.status(404).send({
            //     type    : 'not_found',
            //     message : errMsg
            //   });
            // } else {
              done(null, poem);
            // }
          });
        },
        function(poem, done) {
          // Delete poem comments from poem; iterate through poem.comments and for each
          // find user by id and $pull poem reference from user.poems
          async.each(poem.comments,
            function(commentId, callback) {
              // Delete poem comment
              Comment.findByIdAndRemove(commentId, function(err, comment) {
                if (comment) {
                  console.log('there was a comment');
                  // Delete poem comment reference from user
                  User.findByIdAndUpdate(comment.creator, {
                    '$pull': {
                      comments: commentId
                    }
                  }, function(err, user) {
                    callback();
                  });
                }
              });
            },
            function(err) {
              done(null, poem);
            }
          );
        },
        function(poem, done) {
          // Delete poem from all users' favorites
          User.update({}, {'$pull': {favoritePoems: poem._id}}, { multi: true }, function(err) {
            if (err) {
              console.log('Error in removing poem from User favoritePoems.');
            } else {
              done(null);
            }
          });
        },
      ], function() {
          sucMsg = 'The poem was deleted.';
          console.log(sucMsg.blue);
          res.status(200).send({
            type    : 'success',
            message : sucMsg
          });
      });
    }
  );

  /**
   * Get a user's comments
   */
  // app.get('/api/v1/user/:id/comments',
  //   ensureAuthenticated,
  //   function(req, res, next) {
  //     console.log('\n[GET] /api/v1/user/:id/comments'.bold.green);
  //     console.log('Request body:'.green, req.body);

  //     User.findById(hashids.decryptHex(req.params.id), function(err, user) {
  //       if (err) {
  //         res.message = 'The user could not be found.';
  //         return next(err);
  //       } else if (!user) {
  //         var errMsg = 'The user could not be found.';
  //         console.log(errMsg.red);
  //         res.status(404).send({
  //           type    : 'not_found',
  //           message : errMsg
  //         });
  //       } else {
  //         res.status(200).send({
  //           id          : hashids.encryptHex(user._id),
  //           displayName : user.local.displayName || user.displayName,
  //           joinedDate  : user.createdAt,
  //           email       : user.email, // privacy (don't display to others) need to return only when called by logged-in user
  //           avatarUrl   : user.avatarUrl
  //         });
  //       }
  //     });
  //   }
  // );

  /**
   * Get user's vote for a poem
   */
  app.get('/api/v1/user/:userId/poem/:poemId/vote',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[GET] /api/v1/poem/:poemId/user/:userId/vote'.bold.green);
      console.log('Request body:'.green, req.body);

      var poemId = hashids.decryptHex(req.params.poemId);
      var userId = req.user._id + ''; // for str compare in async.series below
      var sucMsg, errMsg;

      Poem.findById(poemId, function(err, poem) {
        if (err) {
          res.message = 'The poem could not be found.';
          return next(err);
        } else if (!poem) {
          errMsg = 'The poem could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {
          User.findById(userId, function(err, user) {
            if (err) {
              res.message = 'The user could not be found.';
              return next(err);
            } else if (!user) {
              errMsg = 'The user could not be found.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else if (user._id+'' === poem.creator+'') {
              sucMsg = 'The creator cannot vote on own poem.';
              console.log(sucMsg.blue);
              res.status(200).send({
                type    : 'success',
                message : sucMsg
              });
            } else {
              // check if any votes
              if (poem.vote.positive.length === 0 && poem.vote.negative.length === 0) {
                res.status(200).send({
                  type : 'success',
                  vote : 'None'
                });
              } else {
                var vote, i;
                async.waterfall([
                  function(callback) {
                    // check if user voted positive
                    if (poem.vote.positive.indexOf(userId) != -1) {
                      vote = 'up';
                      callback(null, vote);
                    } else {
                      callback(null, vote);
                    }
                  },
                  function(vote, callback) {
                    if (vote == 'up') {
                      callback(null, vote);
                    }
                    // check if user voted negative
                    else if (poem.vote.negative.indexOf(userId) != -1) {
                      vote = 'down';
                      callback(null, vote);
                    } else {
                      callback(null, vote);
                    }
                  },
                  function(vote, callback) {
                    // check if user has not voted
                    if (vote != 'up' && vote != 'down') {
                      vote = 'None';
                      callback(null, vote);
                    } else {
                      callback(null, vote);
                    }
                  }
                ], function(err, vote) {
                  sucMsg = 'Vote: ' + vote;
                  console.log(sucMsg.blue);
                    res.status(200).send({
                      type : 'success',
                      vote : vote
                    });
                });
              }
            }
          });
        }
      });
    }
  );

  /**
   * Vote for a poem
   */
  app.post('/api/v1/user/:userId/poem/:poemId/vote',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:userId/poem/:poemId/vote'.bold.green);
      console.log('Request body:'.green, req.body);

      var poemId = hashids.decryptHex(req.params.poemId);
      var userId = req.user._id;
      var sucMsg;

      Poem.findById(poemId, function(err, poem) {
        if (err) {
          res.message = 'The poem could not be found.';
          return next(err);
        } else if (!poem) {
          var errMsg = 'The poem could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {

          async.series([
            function(callback) {
              // Upvote
              if (req.body.vote === 'up') {
                poem.upvote(userId, function(err, doc) {
                  callback();
                });
              }

              // Downvote
              else if (req.body.vote === 'down') {
                poem.downvote(userId, function(err, doc) {
                  callback();
                });
              }

              // Remove vote
              else if (req.body.vote === 'None') {
                if (poem.upvoted(userId)) {
                  Poem.findByIdAndUpdate(poemId, {
                    '$pull': {
                      'vote.positive': userId
                    }
                  }, function(err, poem) {
                    callback();
                  });
                } else if (poem.downvoted(userId)) {
                  Poem.findByIdAndUpdate(poemId, {
                    '$pull': {
                      'vote.negative': userId
                    }
                  }, function(err, poem) {
                    callback();
                  });
                }
              }
            }
          ], function(err) {
            sucMsg = 'Successful vote.';
            console.log(sucMsg.blue);
            res.status(200).send({
              type    : 'success',
              message : sucMsg
            });
          });
        }
      });
    }
  );

  /**
   * Save a new comment
   */
  app.post('/api/v1/user/:userId/poem/:poemId/comment',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:userId/poem/:poemId/comment'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      var poemId = hashids.decryptHex(req.params.poemId);

      var newComment = new Comment({
        creator : req.user._id,
        poem    : poemId,
        comment : req.body.comment
      });

      async.waterfall([
        function(done) {
          // Save comment
          newComment.save(function(err, comment) {
            done(null, comment._id);
          });
        },
        function(commentId, done) {
          // Add ref to user
          User.findByIdAndUpdate(req.user._id, {
            '$addToSet': {
              comments: commentId
            }
          }, function(err, user) {
            if (!user) {
              errMsg = 'The user could not be found and updated.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              done(null, commentId);
            }
          });
        },
        function(commentId, done) {
          // Add ref to poem
          Poem.findByIdAndUpdate(poemId, {
            '$addToSet': {
              comments: commentId
            }
          }, function(err, poem) {
              if (!poem) {
                errMsg = 'The poem could not be found and updated.';
                console.log(errMsg.red);
                res.status(404).send({
                  type    : 'not_found',
                  message : errMsg
                });
              } else {
                var creatorId = poem.creator;
                done(null, commentId, creatorId);
              }
          });
        }
      ], function(err, commentId, creatorId) {
        if (err) {
          res.message = 'Could not save the comment.';
          return next(err);
        } else {
          sucMsg = 'The comment was saved.';
          console.log(sucMsg.blue);

          // When a new comment is saved, push a notification to the creator if logged in
          // and add comment ref to User's unreadComments[]
          // remove unread comment(s) from [] when creator gets the comment(s)' poem
          if (req.user._id+'' != creatorId+'') {
            User.findByIdAndUpdate(creatorId, {
              '$addToSet': {
                unreadComments : commentId
              }
            },
            function(err, user) {
              var socket = clientSocketsHash[loggedInClientsHash[creatorId]];
              if (socket !== undefined) {
                console.log('emitting newComment event');
                socket.emit('newComment', { msg : 'Someone wrote you a new comment!' });
                res.status(200).send({
                  type      : 'success',
                  message   : sucMsg,
                  commentId : hashids.encryptHex(commentId),
                  creatorId : hashids.encryptHex(creatorId)
                });
              } else {
                console.log('socket is undefined so moving on...');
              }
            });
          } else {
            console.log('Creator so not adding to unreadComments[]');
            res.status(200).send({
              type      : 'success',
              message   : sucMsg,
              commentId : hashids.encryptHex(commentId),
              creatorId : hashids.encryptHex(creatorId)
            });
          }
        }
      });
    }
  );

  /**
   * Get poem status (favorited or not)
   */
  app.get('/api/v1/user/:userId/poem/:poemId/favorite',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[GET] /api/v1/user/:userId/poem/:poemId/favorite'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      var userId = req.user._id;
      var poemId = hashids.decryptHex(req.params.poemId);

      User.findOne({ 'favoritePoems': poemId, '_id': userId }, function(err, user) {
        if (user) {
          sucMsg = 'Poem is favorited.';
          console.log(sucMsg.blue);
          res.status(200).send({
            type    : 'success',
            status  : 'favorited',
            message : sucMsg
          });
        } else if (!user) {
          sucMsg = 'Poem is not favorited.';
          console.log(sucMsg.blue);
          res.status(200).send({
            type    : 'success',
            status  : 'not_favorited',
            message : sucMsg
          });
        }
      });
    }
  );


  /**
   * Favorite a poem
   */
  app.post('/api/v1/user/:userId/poem/:poemId/favorite',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:userId/poem/:poemId/favorite'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;
      var userId = req.user._id;
      var poemId = hashids.decryptHex(req.params.poemId);

      Poem.findById(poemId, function(err, poem) {
        if (err) {
          res.message = 'The poem could not be found.';
          return next(err);
        } else if (!poem) {
          var errMsg = 'The poem could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {

          User.findOne({ 'favoritePoems': poemId, '_id': userId }, function(err, user) {
            if (user) {
              // Remove reference
              User.findByIdAndUpdate(userId, {
                '$pull': {
                  favoritePoems: poemId
                }
              }, function(err, user) {
                if (err) {
                  res.message = 'The user could not be found and updated.';
                  return next(err);
                } else if (!user) {
                  errMsg = 'The user could not be found and updated.';
                  console.log(errMsg.red);
                  res.status(404).send({
                    type    : 'not_found',
                    message : errMsg
                  });
                } else {
                  sucMsg = 'The poem was removed from favorites.';
                  console.log(sucMsg.blue);
                  res.status(200).send({
                    type    : 'success',
                    status  : 'removed',
                    message : sucMsg
                  });
                }
              });
            } else if (!user) {
              // Add reference
              User.findByIdAndUpdate(userId, {
                '$addToSet': {
                  favoritePoems: poemId
                }
              }, function(err, user) {
                if (err) {
                  res.message = 'The user could not be found and updated.';
                  return next(err);
                } else if (!user) {
                  var errMsg = 'The user could not be found and updated.';
                  console.log(errMsg.red);
                  res.status(404).send({
                    type    : 'not_found',
                    message : errMsg
                  });
                } else {
                  var sucMsg = 'The poem was favorited.';
                  console.log(sucMsg.blue);
                  res.status(200).send({
                    type    : 'success',
                    status  : 'favorited',
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
   * Save a new poem
   */
  app.post('/api/v1/user/:id/poem',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:id/poem'.bold.green);
      console.log('Request body:'.green, req.body);

      var sucMsg, errMsg;

      var newPoem           = new Poem();
      newPoem.creator       = req.user._id;
      newPoem.title         = req.body.title;
      newPoem.poem          = req.body.poem;
      newPoem.tags          = req.body.tags;

      var inspirations      = {};
      // var song              = {};

      var videoUrl = req.body.videoUrl;
      if (videoUrl) {
        var domain = extractDomain(videoUrl);
        if (domain === 'www.youtube.com' || domain === 'youtube.com') {
          // https://www.youtube.com/watch?v=zhMww7b3Ha4 => https://www.youtube.com/v/zhMww7b3Ha4
          inspirations.videoUrl = 'https://www.youtube.com/v/' + youtubeIdParser(videoUrl);
        } else if (domain === 'www.vimeo.com' || domain === 'vimeo.com') {
          // http://vimeo.com/98374747 => https://player.vimeo.com/video/98374747
          inspirations.videoUrl = 'https://player.vimeo.com/video/' + vimeoIdParser(videoUrl);
        } else {
          console.log('video url\'s domain not supported:', domain);
        }
      }

      inspirations.imageUrl = req.body.imageUrl;
      // song.artist           = req.body.songArtist;
      // song.title            = req.body.songTitle;
      // song.url              = req.body.songUrl;
      // inspirations.song     = song;
      newPoem.inspirations  = inspirations;

      newPoem.save(function(err, poem) {
        if (err) {
          res.message = 'Could not save new poem.';
          return next(err);
        } else {

          // Add ref to creator
          User.findByIdAndUpdate(req.user._id, {
            '$addToSet': {
              poems: poem._id
            }
          }, function(err, user) {
            if (err) {
              res.message = 'The user could not be found and updated.';
              return next(err);
            } else if (!user) {
              errMsg = 'The user could not be found and updated.';
              console.log(errMsg.red);
              res.status(404).send({
                type    : 'not_found',
                message : errMsg
              });
            } else {
              sucMsg = 'The poem was saved.';
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
  );

  /**
   * Pull down profile image from temporary S3 bucket, process, and then upload
   * to permanent S3 bucket
   * http://www.cheynewallace.com/uploading-to-s3-with-angularjs/
   */
  // app.post('/api/v1/user/:id/avatar',
  //   ensureAuthenticated,
  //   function(req, res, next) {
  //     console.log('\n[POST] /api/v1/user/:id/avatar'.bold.green);
  //     console.log('Request body:'.green, req.body);

  //     var fileName = req.body.fileName;
  //     var errMsg, sucMsg;

  //     async.waterfall([
  //       function(done) {

  //         // Download image from temp bucket
  //         var localPath = './' + fileName;

  //         var params = {
  //           localFile: localPath,
  //           s3Params: {
  //             Bucket: auth.amazon_s3.BUCKET_TEMPORARY,
  //             Key: fileName
  //           }
  //         };

  //         var downloader = s3Client.downloadFile(params);

  //         downloader.on('error', function(err) {
  //           console.log('Unable to download from temp bucket:', err.stack);
  //         });

  //         downloader.on('end', function() {
  //           sucMsg = 'Successful download from temp bucket';
  //           console.log(sucMsg.blue);
  //           done(null, localPath);
  //         });
  //       },
  //       // PROCESS IMAGE
  //       function(localPath, done) {

  //         // Upload image to permanent bucket
  //         var destPath = hashids.encryptHex(req.user._id) + '/profile' + '/' + fileName;

  //         var params = {
  //           localFile: localPath,
  //           s3Params: {
  //             Bucket: auth.amazon_s3.BUCKET_PERMANENT,
  //             Key: destPath
  //           }
  //         };
  //         var uploader = s3Client.uploadFile(params);

  //         uploader.on('error', function(err) {
  //           console.log('Unable to upload to permanent bucket:', err.stack);
  //         });

  //         uploader.on('end', function() {
  //           sucMsg = 'Successful upload to permanent bucket';
  //           console.log(sucMsg.blue);

  //           // delete temp file
  //           fs.unlink(localPath, function(err) {
  //             if (err) {
  //               console.log('Unable to delete temp file:', err.stack);
  //             } else {
  //               sucMsg = 'Successful deletion of temporary file';
  //               console.log(sucMsg.blue);
  //             }
  //           });
  //           done(null, destPath);
  //         });
  //       },
  //       function(destPath, done) {
  //         var avatarUrl = s3.getPublicUrlHttp(auth.amazon_s3.BUCKET_PERMANENT, destPath);

  //         // save url to db
  //         User.findById(req.user._id, function(err, user) {
  //           if (err) {
  //             res.message = 'The user could not be found.';
  //             return next(err);
  //           } else if (!user) {
  //             var errMsg = 'The user could not be found.';
  //             console.log(errMsg.red);
  //             res.status(404).send({
  //               type    : 'not_found',
  //               message : errMsg
  //             });
  //           } else {
  //             user.avatarUrl = avatarUrl || user.avatarUrl;
  //             user.save(function(err) {
  //               if (err) {
  //                 res.message = 'The user could not be saved to the database.';
  //                 return next(err);
  //               } else {
  //                 done(null, avatarUrl);
  //               }
  //             });
  //           }
  //         });
  //       }
  //     ], function(err, avatarUrl) {
  //         console.log('Image found at:', avatarUrl);
  //         res.status(200).send({
  //           type            : 'success',
  //           avatarUrl : avatarUrl
  //         });
  //     });
  //   }
  // );


  /**
   * Upload inspirational image for poem
   */
  app.post('/api/v1/user/:id/poem/image',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:id/poem/image'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;

      async.waterfall([
        function(done) {

          // Upload avatar to S3
          var form = new multiparty.Form();
          form.parse(req, function(err, fields, files) {
            var file        = files.file[0];
            var contentType = file.headers['content-type'];
            var extension   = file.path.substring(file.path.lastIndexOf('.'));
            var destPath    = hashids.encryptHex(req.user._id) + '/poems/' + uuid.v4() + extension; // file.originalFilename

            // server side file type checker
            if (contentType !== 'image/png' && contentType !== 'image/jpeg' && contentType !== 'image/jpg' &&
                contentType !== 'image/gif') {
              errMsg = 'Unsupported file type for image upload: ' + contentType;
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
                Bucket: auth.amazon_s3.BUCKET_PERMANENT,
                Key: destPath
              }
            };

            var uploader = s3Client.uploadFile(params);

            uploader.on('error', function(err) {
              errMsg = 'Unable to upload image.';
              console.log(errMsg.red);
              return next(err);
            });

            uploader.on('end', function() {
              sucMsg = 'Successful upload of image.';
              console.log(sucMsg.blue);
              done(null, destPath);
            });
          });
        },
        function(destPath, done) {
          var imageUrl = s3.getPublicUrlHttp(auth.amazon_s3.BUCKET_PERMANENT, destPath);
          done(null, imageUrl);
        }
      ], function(err, imageUrl) {
          console.log('Image found at:', imageUrl);
          res.status(200).send({
            type     : 'success',
            imageUrl : imageUrl
          });
      });
    }
  );

  /**
   * Upload avatar for user profile
   */
  app.post('/api/v1/user/:id/avatar',
    ensureAuthenticated,
    function(req, res, next) {
      console.log('\n[POST] /api/v1/user/:id/avatar'.bold.green);
      console.log('Request body:'.green, req.body);

      var errMsg, sucMsg;

      async.waterfall([
        function(done) {

          // Upload avatar to S3
          var form = new multiparty.Form();
          form.parse(req, function(err, fields, files) {
            var file        = files.file[0];
            console.log(file);
            var contentType = file.headers['content-type'];
            var extension   = file.path.substring(file.path.lastIndexOf('.'));
            var destPath    = hashids.encryptHex(req.user._id) + '/profile/' + uuid.v4() + extension; // file.originalFilename

            // server side file type checker
            if (contentType !== 'image/png' && contentType !== 'image/jpeg' && contentType !== 'image/jpg') {
              errMsg = 'Unsupported file type for image upload: ' + contentType;
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
                Bucket: auth.amazon_s3.BUCKET_PERMANENT,
                Key: destPath
              }
            };

            var uploader = s3Client.uploadFile(params);

            uploader.on('error', function(err) {
              errMsg = 'Unable to upload avatar.';
              console.log(errMsg.red);
              return next(err);
            });

            uploader.on('end', function() {
              sucMsg = 'Successful upload of avatar.';
              console.log(sucMsg.blue);
              done(null, destPath);
            });
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
              errMsg = 'The user could not be found.';
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
            type      : 'success',
            avatarUrl : avatarUrl
          });
      });
    }
  );

};