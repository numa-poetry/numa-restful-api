'use strict';

// modules ---------------------------------------------------------------------
var crypto    = require('crypto');
var colors    = require('colors');
var moment    = require('moment');
var jwt       = require('jwt-simple');
var request   = require('request');
var qs        = require('querystring');
var UserModel = require('./models/user.js');
var auth      = require('./config/auth');

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

  function createToken(keepLoggedIn, user) {
    var expires, payload;

    if (keepLoggedIn) {
      expires = moment().add(7, 'days').valueOf();
      console.log('long session token set'.yellow);
    } else {
      expires = moment().add(1, 'hour').valueOf();
      console.log('short session token set'.yellow);
    }
    payload = {
      user  : user,
      'sub' : user._id,           // subject (identifies the principal that is the subject of the JWT)
      // 'iss' : req.hostname,       // issuer (specifies entity making the request)
      'iat' : moment().valueOf(), // The iat (issued at) claim identifies the time at which the JWT was issued.
      'exp' : expires             // expires (lifetime of token)
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
      UserModel.findById(req.params.id, function(err, user) {
        if (err) {
          console.log(err);
          res.status(500).send({
            type    : 'internal_server_error',
            message : 'The user is not authorized to access this resource.'
          });
        } else if (!user) {
          errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {

          var token   = req.headers.authorization.split(' ')[1];
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
        }
      });
    }
  }

  /**
   * Local signup
   */
  app.post('/api/v1/signup',
    function(req, res) {
      console.log('\n[POST] /api/v1/signup'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var errMsg;

        // Verify username isn't taken
        UserModel.findOne({
          'local.username' : req.body.username
        }, function(err, user) {
          if (err) {
            console.log(err);
            res.status(500).send({
              type    : 'internal_server_error',
              message : 'The user could not be signed up'
            });
          } else if (user) {
            errMsg = 'This username is already taken.';
            console.log(errMsg.red);
            res.status(400).send({
              type    : 'bad_request',
              message : errMsg
            });
          } else {

            // Verify email isn't taken
            UserModel.findOne({
              'local.email' : req.body.email
            }, function(err, user) {
              if (err) {
                console.log(err);
                res.status(500).send({
                  type    : 'internal_server_error',
                  message : 'The user could not be signed up'
                });
              } else if (user) {
                errMsg = 'This email is already taken.';
                console.log(errMsg.red);
                res.status(400).send({
                  type    : 'bad_request',
                  message : errMsg
                });
              } else {

                // Build new user
                var newUser             = new UserModel();
                newUser.local.username  = req.body.username;
                newUser.local.email     = req.body.email;
                newUser.local.password  = newUser.generateHash(req.body.password);

                // Save new user to the database
                newUser.save(function(err) {
                  if (err) {
                    console.log(err);
                    res.status(500).send({
                      type    : 'internal_server_error',
                      message : err
                    });
                  } else {
                    newUser = newUser.toObject();
                    delete newUser.local.password;
                    var token = createToken(req.body.keepLoggedIn, newUser);
                    res.status(201).send({
                      id    : newUser._id,
                      token : token
                    });
                  }
                });
              }
            });
          }
        });
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be signed up in.'
        });
      }
    }
  );

  /**
   * Local login
   */
  app.post('/api/v1/login',
    function(req, res) {
      console.log('\n[POST] /api/v1/login'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var errMsg;

        // http://devsmash.com/blog/implementing-max-login-attempts-with-mongoose
        UserModel.getAuthenticated(req.body.username, req.body.password,
          function(err, user, reason) {
            if (err) {
              throw err;
            } else if (user) {
              console.log('login successful'.green);
              user = user.toObject();
              delete user.password;
              var token = createToken(req.body.keepLoggedIn, user);
              res.status(201).send({
                id    : user._id,
                token : token
              });
            } else {

              // otherwise we can determine why we failed
              var reasons = UserModel.failedLogin;
              switch (reason) {
                case reasons.NOT_FOUND:
                  errMsg = 'The user could not be found.';
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
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be logged in.'
        });
      }
    }
  );

  /**
   * Login with Facebook
   */
  app.post('/auth/facebook',
    function(req, res) {
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
            UserModel.findOne({ 'facebook': profile.id }, function(err, existingUser) {
              if (existingUser) {
                return res.status(409).send({ message: 'There is already a Facebook account that belongs to you' });
              } else {

                var token   = req.headers.authorization.split(' ')[1];
                var payload = jwt.decode(token, auth.TOKEN_SECRET);

                UserModel.findById(payload.sub, function(err, user) {
                  if (!user) {
                    return res.status(400).send({ message: 'User not found' });
                  } else {
                    user.facebook    = profile.id;
                    user.displayName = user.displayName || profile.name;

                    user.save(function(err) {
                      if (err) {
                        console.log(err);
                        res.status(500).send({
                          type    : 'internal_server_error',
                          message : err
                        });
                      } else {
                        var token = createToken(undefined /* keepLoggedIn */, user);
                        res.status(200).send({
                          id       : user._id,
                          token    : token,
                          username : user.displayName
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
            UserModel.findOne({ 'facebook': profile.id }, function(err, existingUser) {
              if (existingUser) {
                console.log('3b existing user');
                var token = createToken(undefined /* keepLoggedIn */, existingUser);
                res.status(200).send({
                  id       : existingUser._id,
                  token    : token,
                  username : existingUser.displayName
                });
              } else {
                console.log('3b new user');
                var newUser         = new UserModel();
                newUser.facebook    = profile.id;
                newUser.displayName = profile.name;

                newUser.save(function(err) {
                  if (err) {
                    console.log(err);
                    res.status(500).send({
                      type    : 'internal_server_error',
                      message : err
                    });
                  } else {
                    var token = createToken(undefined /* keepLoggedIn */, newUser);
                    res.status(201).send({
                      id       : newUser._id,
                      token    : token,
                      username : newUser.displayName
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
    function(req, res) {
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
            UserModel.findOne({ 'github': profile.id }, function(err, existingUser) {
              if (existingUser) {
                return res.status(409).send({ message: 'There is already a GitHub account that belongs to you' });
              } else {
                var token   = req.headers.authorization.split(' ')[1];
                var payload = jwt.decode(token, auth.TOKEN_SECRET);

                UserModel.findById(payload.sub, function(err, user) {
                  if (!user) {
                    return res.status(400).send({ message: 'User not found' });
                  } else {
                    user.github      = profile.id;
                    user.displayName = user.displayName || profile.name;

                    user.save(function(err) {
                      if (err) {
                        console.log(err);
                        res.status(500).send({
                          type    : 'internal_server_error',
                          message : err
                        });
                      } else {
                        var token = createToken(undefined /* keepLoggedIn */, user);
                        res.status(200).send({
                          id       : user._id,
                          token    : token,
                          username : user.displayName
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
            UserModel.findOne({ 'github': profile.id }, function(err, existingUser) {
              if (existingUser) {
                console.log('3b existing user');
                var token = createToken(undefined /* keepLoggedIn */, existingUser);
                res.status(200).send({
                  id       : existingUser._id,
                  token    : token,
                  username : existingUser.displayName
                });
              } else {
                console.log('3b new user');
                var newUser         = new UserModel();
                newUser.github      = profile.id;
                newUser.displayName = profile.name;

                newUser.save(function(err) {
                  if (err) {
                    console.log(err);
                    res.status(500).send({
                      type    : 'internal_server_error',
                      message : err
                    });
                  } else {
                    var token = createToken(undefined /* keepLoggedIn */, newUser);
                    res.status(201).send({
                      id       : newUser._id,
                      token    : token,
                      username : newUser.displayName
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
    function(req, res) {
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
            UserModel.findOne({ 'google': profile.sub }, function(err, existingUser) {
              if (existingUser) {
                return res.status(409).send({ message: 'There is already a Google account that belongs to you' });
              } else {
                var token = req.headers.authorization.split(' ')[1];
                var payload = jwt.decode(token, auth.TOKEN_SECRET);

                UserModel.findById(payload.sub, function(err, user) {
                  if (!user) {
                    return res.status(400).send({ message: 'User not found' });
                  }
                  user.google      = profile.sub;;
                  user.displayName = user.displayName || profile.name;

                  user.save(function(err) {
                    if (err) {
                      console.log(err);
                      res.status(500).send({
                        type    : 'internal_server_error',
                        message : err
                      });
                    } else {
                      var token = createToken(undefined /* keepLoggedIn */, user);
                      res.status(200).send({
                        id       : user._id,
                        token    : token,
                        username : user.displayName
                      });
                    }
                  });
                });
              }
            });
          } else {
            console.log('PROFILE:', profile);

            // Step 3b. Create a new user account or return an existing one.
            UserModel.findOne({ 'google': profile.sub }, function(err, existingUser) {
              if (existingUser) {
                console.log('3b existingUser');
                // return res.send({ token: createToken(req, existingUser) });
                var token = createToken(undefined /* keepLoggedIn */, existingUser);
                res.status(200).send({
                  id       : existingUser._id,
                  token    : token,
                  username : existingUser.displayName
                });
              } else {
                console.log('3b new user');
                var newUser         = new UserModel();
                newUser.google      = profile.sub;
                newUser.displayName = profile.name;

                newUser.save(function(err) {
                  if (err) {
                    console.log(err);
                    res.status(500).send({
                      type    : 'internal_server_error',
                      message : err
                    });
                  } else {
                    var token = createToken(undefined /* keepLoggedIn */, newUser);
                    res.status(201).send({
                      id       : newUser._id,
                      token    : token,
                      username : newUser.displayName
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
    ensureAuthenticated,
    function(req, res) {
      console.log('\n[GET] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        // req.user retrieved from ensureAuthenticated() middleware
        res.status(200).send({
          id       : req.user._id,
          username : req.user.local.username,
          email    : req.user.local.email
        });
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be retrieved.'
        });
      }
    }
  );

  /**
   * Delete a user
   */
  app.delete('/api/v1/user/:id/',
    ensureAuthenticated,
    function(req, res) {
      console.log('\n[DELETE] /api/v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var errMsg, sucMsg;

        UserModel.findByIdAndRemove(req.user._id, function(err, user) {
          if (err) {
            console.log(err);
            res.status(500).send({
              type    : 'internal_server_error',
              message : 'The user could not be deleted'
            });
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
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be deleted'
        });
      }
    }
  );

  /**
   * Get all users
   */
  app.get('/api/v1/user',
    function(req, res) {
      console.log('\n[GET] /api/v1/user'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var errMsg;

        UserModel.find(function(err, users) {
          if (err) {
            console.log(err);
            res.status(500).send({
              type    : 'internal_server_error',
              message : 'All users could not be retrieved.'
            });
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
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'All users could not be retrieved.'
        });
      }
    }
  );

};