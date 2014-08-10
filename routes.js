'use strict';

// modules ---------------------------------------------------------------------
var passport = require('./passport');
var crypto   = require('crypto');
var colors   = require('colors');

// res.status().body()

// routes ----------------------------------------------------------------------
module.exports = function(app, passport) {

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