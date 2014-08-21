'use strict';

// modules ---------------------------------------------------------------------
var crypto    = require('crypto');
var colors    = require('colors');
var moment    = require('moment');
var jwt       = require('jwt-simple');
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
      'iss' : user._id,           // issuer (specifies entity making the request)
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

          // Verify user is token issuer
          if (payload.iss !== req.params.id) {
            errMsg = 'The user is not the token issuer.';
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
  app.post('/api/v1/user/signup',
    function(req, res) {
      console.log('\n[POST] /api/v1/user/signup'.bold.green);
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
  app.post('/api/v1/user/login',
    function(req, res) {
      console.log('\n[POST] /api/v1/user/login'.bold.green);
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
          res.status(200).send(users); // sanitize!!
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