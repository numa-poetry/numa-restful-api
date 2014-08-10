'use strict';

// modules ---------------------------------------------------------------------
var LocalStrategy  = require('passport-local').Strategy;
var RedditStrategy = require('passport-reddit').Strategy;
var GitHubStrategy = require('passport-github').Strategy;
var auth           = require('./config/auth.js');
var userModel      = require('./models/user.js');
var colors         = require('colors');

// authentication variables ----------------------------------------------------
var REDDIT_CLIENT_ID     = auth.reddit.CLIENT_ID;
var REDDIT_CLIENT_SECRET = auth.reddit.CLIENT_SECRET;
var REDDIT_CALLBACK_URL  = auth.reddit.CALLBACK_URL;

var GITHUB_CLIENT_ID     = auth.github.CLIENT_ID;
var GITHUB_CLIENT_SECRET = auth.github.CLIENT_SECRET;
var GITHUB_CALLBACK_URL  = auth.github.CALLBACK_URL;

module.exports = function(passport) {

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    userModel.findById(id, function(err, user) {
      done(err, user);
    });
  });

// local signup strategy -------------------------------------------------------
  passport.use('local-signup', new LocalStrategy({
    usernameField     : 'email',
    passwordField     : 'password',
    passReqToCallback : true // allow us to pass back the entire require to the callback
  }, function(req, email, password, done) {
    var errMsg;

    process.nextTick(function() {
      userModel.findOne({
        'local.userName' : req.body.userName,
      }, function(err, user) {
        if (err) {
          return done(err);
        }
        if (user) {
          errMsg = 'Username is already taken';
          console.log(errMsg.red);
          return done(null, false, { message : errMsg });
        }
        var newUser = new userModel();
        newUser.local.email = email;
        newUser.local.password = newUser.generateHash(password);
        newUser.local.userName = req.body.userName;

        newUser.save(function(err) {
          if (err) {
            throw err;
          }
          return done(null, newUser);
        });
      });
    });
  }));

// local login strategy --------------------------------------------------------
  passport.use('local-login', new LocalStrategy({
    usernameField     : 'userNameOrEmail',
    passwordField     : 'password',
    passReqToCallback : true,
  }, function(req, userNameOrEmail, password, done) {
    var errMsg;

    userModel.findOne({
      'local.email' : userNameOrEmail
    }, function(err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        userModel.findOne({
          'local.userName' : userNameOrEmail
        }, function(err, user) {
          if (err) {
            return done(err);
          }
          if (!user) {
            errMsg = 'No user found with that username or email';
            console.log(errMsg.red);
            return done(null, false, { message : errMsg });
          }
          if (!user.validPassword(password)) {
            errMsg = 'Credentials don\'t match';
            console.log(errMsg.red);
            return done(null, false, { message : errMsg });
          }
          return done(null, user);
        });
      }
      if (user) {
        if (!user.validPassword(password)) {
          errMsg = 'Credentials don\'t match';
          console.log(errMsg.red);
          return done(null, false, { message : errMsg });
        }
        return done(null, user);
      }
    });
  }));

// reddit strategy -------------------------------------------------------------
  passport.use(new RedditStrategy({
      clientID     : REDDIT_CLIENT_ID,
      clientSecret : REDDIT_CLIENT_SECRET,
      callbackURL  : REDDIT_CALLBACK_URL
    },
    function(accessToken, refreshToken, profile, done) {
      // asynchronous verification, for effect...
      process.nextTick(function () {
        console.log('Reddit profile:', profile);
        return done(null, profile);
      });
    }
  ));

// github strategy -------------------------------------------------------------
  passport.use(new GitHubStrategy({
      clientID     : GITHUB_CLIENT_ID,
      clientSecret : GITHUB_CLIENT_SECRET,
      callbackURL  : GITHUB_CALLBACK_URL
    },
    function(accessToken, refreshToken, profile, done) {
      // asynchronous verification, for effect...
      process.nextTick(function () {
        console.log('Github profile:', profile);
        return done(null, profile);
      });
    }
  ));

};
