'use strict';

// modules ---------------------------------------------------------------------
var RedditStrategy = require('passport-reddit').Strategy;
var GitHubStrategy = require('passport-github').Strategy;
var auth           = require('./auth.js');

// authentication variables ----------------------------------------------------
var REDDIT_CLIENT_ID     = auth.reddit.CLIENT_ID;
var REDDIT_CLIENT_SECRET = auth.reddit.CLIENT_SECRET;
var REDDIT_CALLBACK_URL  = auth.reddit.CALLBACK_URL;

var GITHUB_CLIENT_ID     = auth.github.CLIENT_ID;
var GITHUB_CLIENT_SECRET = auth.github.CLIENT_SECRET;
var GITHUB_CALLBACK_URL  = auth.github.CALLBACK_URL;

module.exports = function(passport) {

  // Passport session setup.
  //   To support persistent login sessions, Passport needs to be able to
  //   serialize users into and deserialize users out of the session.  Typically,
  //   this will be as simple as storing the user ID when serializing, and finding
  //   the user by ID when deserializing.  However, since this example does not
  //   have a database of user records, the complete profile is
  //   serialized and deserialized.
  passport.serializeUser(function(user, done) {
    done(null, user);
  });

  passport.deserializeUser(function(obj, done) {
    done(null, obj);
  });

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
