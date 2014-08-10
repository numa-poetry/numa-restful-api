'use strict';

// modules ---------------------------------------------------------------------
var passport   = require('./passport');
var crypto     = require('crypto');
var colors     = require('colors');
var moment     = require('moment');
var jwt        = require('jwt-simple');
var expressJwt = require('express-jwt');
var userModel  = require('./models/user.js');

// security functions ----------------------------------------------------------
var algorithm = 'aes128';
var key       = 'key';

function encrypt(key, text) {
  var cipher    = crypto.createCipher(algorithm, key);
  var encrypted = cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
  return encrypted;
}

function decrypt(key, encrypted) {
  var decipher  = crypto.createDecipher(algorithm, key);
  var decrypted = decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
  return decrypted;
}

function signToken(keepLoggedIn, jwtTokenSecret, userId) {
  var expires, token;

  if (keepLoggedIn) {
    expires = moment().add(2, 'weeks').valueOf();
    console.log('long session token set'.yellow);
  } else {
    expires = moment().add(1, 'hour').valueOf();
    console.log('short session token set'.yellow);
  }
  token = jwt.encode({
    'iss' : userId, // issuer (specifies entity making the request)
    'exp' : expires // expires (lifetime of token)
  }, jwtTokenSecret);
  return token;
}

// routes ----------------------------------------------------------------------
module.exports = function(app, passport) {

  var jwtTokenSecret = app.get('jwtTokenSecret');

  // Simple route middleware to ensure user is authenticated.
  //   Use this route middleware on any resource that needs to be protected.  If
  //   the request is authenticated (typically via a persistent login session),
  //   the request will proceed.  Otherwise, the user will be redirected to the
  //   login page.
  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { 
      return next(); 
    }
    res.redirect('/login');
  }

  app.get('/', function(req, res){
    console.log('\n[GET] /'.bold.green);
    console.log('Request body:'.green, req.body);
    res.render('index');
  });

  app.get('/profile', ensureAuthenticated, function(req, res){
    console.log('\n[GET] /profile'.bold.green);
    console.log('Request body:'.green, req.body);
    res.render('profile', { 
      user: JSON.stringify(req.user , undefined, 2)
    });
  });

  app.get('/logout', function(req, res){
    console.log('\n[GET] /logout'.bold.green);
    console.log('Request body:'.green, req.body);
    req.logout();
    res.redirect('/');
  });

  /**
   * Local signup
   */
  app.post('/api/user/signup', function(req, res) {
    console.log('\n[POST] /api/user/signup'.bold.green);
    console.log('Request body:'.green, req.body);

    passport.authenticate('local-signup', function(err, user, info) {
      if (err) {
        console.log(err);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be authenticated.'
        });
      } 
      if (!user) {
        console.log(err);
        res.status(404).send({
          type    : 'not_found',
          message : 'The user could not be found.'
        });
      } 
      var resObj      = {};
      resObj.id       = user._id;
      resObj.userName = user.local.userName;
      resObj.email    = user.local.email;
      resObj.token    = signToken(req.body.keepLoggedIn, jwtTokenSecret, user._id);
      console.log('resObj:', resObj);
      res.status(201).send(resObj);
    })(req, res);
  });

  /**
   * Local login
   */
  app.post('/api/user/login', function(req, res) {
    console.log('\n[POST] /api/user/login'.bold.green);
    console.log('Request body:'.green, req.body);

    passport.authenticate('local-login', function(err, user, info) {
      if (err) {
        console.log(err);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be authenticated.'
        });
      }
      if (!user) {
        console.log(err);
        res.status(404).send({
          type    : 'not_found',
          message : 'The user could not be found.'
        });
      }
      req.login(user, function(err) {
        if (err) {
          console.log(err);
        }
        var resObj      = {};
        resObj.id       = user._id;
        resObj.userName = user.local.userName;
        resObj.email    = user.local.email;
        resObj.token    = signToken(req.body.keepLoggedIn, jwtTokenSecret, user._id);
        console.log('resObj:', resObj);
        res.status(201).send(resObj);
      })
    })(req, res);
  });

  /**
   * Local logout
   */
  app.get('/api/user/logout',
    expressJwt({ secret : jwtTokenSecret }),
    function(req, res) {
      console.log('\n[GET] /api/user/logout'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        req.logout();
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be logged out.'
        });
      }
    });

  /**
   * Delete user account
   */
  app.delete('/api/user/:id/',
    expressJwt({ secret : jwtTokenSecret }),
    function(req, res) {
      console.log('\n[GET] /api/user/:id'.bold.green);
      console.log('Request body:'.green, req.body);

      try {
        var token        = req.headers.authentication.split(' ')[1];
        var decodedToken = jwt.decode(token, jwtTokenSecret);

        // verify user token is valid, not expired
        if (moment().valueOf() <= decodedToken.exp) {
          var id = req.params.id;

          userModel.findOneByIdAndRemove(id, function(err, user) {
            if (err) {
              console.log(err);
              res.status(500).send({
                type    : 'internal_server_error',
                message : 'The user could not be deleted.'
              });
            }
            if (!user) {
              console.log('The user could not be found');
              res.status(404).send({
                type    : 'not_found',
                message : 'The user could not be found.'
              });
            }
            console.log('The user was deleted.');
            res.status(204).send({
              type    : 'success',
              message : 'The user was deleted.'
            });
          })
        } else {
          console.log('The token is expired');
          res.status(498).send({
            type    : 'token_expired',
            message : 'The token is expired.'
          });
        }
      } catch (ex) {
        console.log(ex);
        res.status(500).send({
          type    : 'internal_server_error',
          message : 'The user could not be deleted.'
        });
      }
    });

  /**
   * Get all users
   */
  app.get('/api/user', function(req, res) {
    console.log('\n[GET] /api/user'.bold.green);
    console.log('Request body:'.green, req.body);

    try {
      userModel.find(function(err, users) {
        if (err) {
          console.log(err);
          res.status(500).send({
            type    : 'internal_server_error',
            message : 'All users could not be found.'
          });
        }
        if (!users) {
          console.log('All users could not be found');
          res.status(404).send({
            type    : 'not_found',
            message : 'All users could not be found.'
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
  })
// Reddit authentication -------------------------------------------------------
  app.get('/auth/reddit', function(req, res, next){
    console.log('\n[GET] /auth/reddit'.bold.green);
    console.log('Request body:'.green, req.body);
    req.session.state = crypto.randomBytes(32).toString('hex');
    passport.authenticate('reddit', {
      state    : req.session.state,
      // duration : 'permanent'
    })(req, res, next);
  });

  app.get('/auth/reddit/callback', function(req, res, next){
    console.log('\n[GET] /auth/reddit/callback'.bold.green);
    console.log('Request body:'.green, req.body);
    // Check for origin via state token
    if (req.query.state == req.session.state){
      passport.authenticate('reddit', {
        successRedirect: '/profile',
        failureRedirect: '/'
      })(req, res, next);
    }
    else {
      next( new Error(403) );
    }
  });

// Github authentication -------------------------------------------------------
  app.get('/auth/github', function(req, res, next){
    console.log('\n[GET] /auth/github/'.bold.green);
    console.log('Request body:'.green, req.body);
    passport.authenticate('github', {
    })(req, res, next);
  });

  app.get('/auth/github/callback', function(req, res, next){
    console.log('\n[GET] /auth/github/callback'.bold.green);
    console.log('Request body:'.green, req.body);
    passport.authenticate('github', { 
      successRedirect: '/profile',
      failureRedirect: '/'
    })(req, res, next);
  });

};