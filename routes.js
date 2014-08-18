'use strict';

// modules ---------------------------------------------------------------------
var crypto    = require('crypto');
var colors    = require('colors');
var moment    = require('moment');
var jwt       = require('jwt-simple');
var userModel = require('./models/user.js');
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

  /**
   * Middleware
   */
  function ensureAuthenticated(req, res, next) {
    var errMsg;

    if (!req.headers.authorization) {
      errMsg = 'The user is not authorized to access this resource.'
      console.log(errMsg.red);
      res.status(401).send({
        type    : 'unauthorized',
        message : errMsg
      });
    } else {    
      var token   = req.headers.authorization.split(' ')[1];
      var payload = jwt.decode(token, auth.TOKEN_SECRET);

      if (payload.exp <= Date.now()) {
        errMsg = 'The user\'s session token has expired.'
        console.log(errMsg.red);
        res.status(498).send({
          type    : 'token_expired',
          message : errMsg
        });
      } else {
        req.user = payload.user;
        next();
      }
    }
  }

  /**
   * Local signup
   */
  app.post('/v1/user/signup', function(req, res) {
    console.log('\n[POST] /v1/user/signup'.bold.green);
    console.log('Request body:'.green, req.body);

    try {
      var errMsg;

      // Verify username isn't taken
      userModel.findOne({
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
          userModel.findOne({
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
              var newUser             = new userModel();
              newUser.local.username  = req.body.username;
              newUser.local.email     = req.body.email;
              newUser.local.password  = newUser.generateHash(req.body.password);
              newUser.signupTimestamp = moment().valueOf();

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
  });

  /**
   * Local login
   */
  app.post('/v1/user/login', function(req, res) {
    console.log('\n[POST] /v1/user/login'.bold.green);
    console.log('Request body:'.green, req.body);

    try {
      var errMsg;

      // Verify user exists
      userModel.findOne({
        'local.username' : req.body.username
      }, function(err, user) {
        if (err) {
          console.log(err);
          res.status(500).send({
            type    : 'internal_server_error',
            message : err
          });
        } else if (!user) {
          errMsg = 'The user could not be found.';
          console.log(errMsg.red);
          res.status(404).send({
            type    : 'not_found',
            message : errMsg
          });
        } else {

          // Verify password matches
          user.comparePassword(req.body.password, function(err, isMatch) {
            if (isMatch) {
              errMsg = 'Wrong email and/or password.';
              console.log(errMsg.red);
              res.status(400).send({
                type    : 'bad_request',
                message : errMsg
              });
            } else {
              user = user.toObject();
              delete user.password;
              var token = createToken(req.body.keepLoggedIn, user);
              res.status(201).send({
                id   : user._id,
                token : token
              });
            }
          });
        }
      });
    } catch (ex) {
      console.log(ex);
      res.status(500).send({
        type    : 'internal_server_error',
        message : 'The user could not be logged in.'
      });
    }
  });

  /**
   * Get a user by id
   */
  app.get('/v1/user/:id',
    ensureAuthenticated,
    function(req, res) {
      console.log('\n[GET] /v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var errMsg;

        userModel.findById(req.user._id, function(err, user) {
          if (err) {
            console.log(err);
            res.status(500).send({
              type    : 'internal_server_error',
              message : err
            });
          } else if (!user) {
            errMsg = 'The user could not be found.';
            console.log(errMsg.red);
            res.status(404).send({
              type    : 'not_found',
              message : errMsg
            });
          } else {
            res.status(200).send({
              id       : user._id,
              username : user.local.username,
              email    : user.local.email                
            });
          }
        });
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be retrieved.'
        });
      }
    });

  /**
   * Delete user account
   */
  app.delete('/v1/user/:id/',
    ensureAuthenticated,
    function(req, res) {
      console.log('\n[DELETE] /v1/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var errMsg, sucMsg;

        userModel.findByIdAndRemove(req.user._id, function(err, user) {
          if (err) {
            console.log(err);
            res.status(500).send({
              type    : 'internal_server_error',
              message : err
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
    });

  /**
   * Get all users
   */
  app.get('/v1/user', function(req, res) {
    console.log('\n[GET] /v1/user'.bold.green);
    console.log('Request body:'.green, req.body);

    try {
      // userModel.find(function(err, users) {
      //   if (err) {
      //     console.log(err);
      //     res.status(500).send({
      //       type    : 'internal_server_error',
      //       message : 'All users could not be found.'
      //     });
      //   }
      //   if (!users) {
      //     console.log('All users could not be found');
      //     res.status(404).send({
      //       type    : 'not_found',
      //       message : 'All users could not be found.'
      //     });
      //   }
      //   res.status(200).send(users); // sanitize!!
      // });
    } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'All users could not be retrieved.'
        });      
    }
  });

};