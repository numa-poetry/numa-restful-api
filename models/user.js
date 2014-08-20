'use strict';

var mongoose    = require('mongoose');
var Schema      = mongoose.Schema;
var bcrypt      = require('bcrypt-nodejs');
var timestamps  = require('mongoose-timestamp');
var SALT_FACTOR = 10;

/**
 * User Schema
 */
var UserSchema = new Schema({

  local : {
    username : String,
    email    : String,
    password : String
  },

});

/**
 * Plugins
 */
UserSchema.plugin(timestamps);

/**
 * Model methods
 */
UserSchema.methods.comparePassword = function(password, done) {
  bcrypt.compare(password, this.password, function(err, isMatch) {
    done(err, isMatch);
  });
};

UserSchema.methods.generateHash = function(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(SALT_FACTOR), null);
};

UserSchema.methods.validPassword = function(password) {
  return bcrypt.compareSync(password, this.local.password);
};

// Override
UserSchema.methods.toJSON = function() {
  var user = this.toObject();
  delete user._id;
  delete user.__v;
  delete user.local.email;
  delete user.local.password;
  delete user.updatedAt;
  return user;
};

/**
 * Serial middleware
 */
UserSchema.pre('save', function(next) {
  var user = this;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    bcrypt.hash(user.local.password, salt, function(err, hash) {
      user.local.password = hash;
      next();
    });
  });
});

module.exports = mongoose.model('User', UserSchema);