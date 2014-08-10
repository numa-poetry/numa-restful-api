'use strict';

var mongoose    = require('mongoose');
var Schema      = mongoose.Schema;
var bcrypt      = require('bcrypt-nodejs');
var SALT_FACTOR = 10;

/**
 * User Schema
 */
var userSchema = new Schema({

  local : {
    userName : String,
    email    : String,
    password : String
  },

  reddit : {
    id       : String,
    token    : String,
    name     : String
  },

  github : {
    id       : String,
    token    : String,
    username : String,
    email    : String
  }

});

/**
 * Encryption methods
 */
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) {
      return cb(err);
    }
    cb(null, isMatch);
  });
};

userSchema.methods.generateHash = function(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(SALT_FACTOR), null);
};

userSchema.methods.validPassword = function(password) {
  return bcrypt.compareSync(password, this.local.password);
};

module.exports = mongoose.model('User', userSchema);