'use strict';

var mongoose    = require('mongoose');
var Schema      = mongoose.Schema;
var bcrypt      = require('bcrypt-nodejs');
var SALT_FACTOR = 10;

/**
 * User Schema
 */
var userSchema = new Schema({

  signupTimestamp : Number,

  local : {
    username : String,
    email    : String,
    password : String
  },

});

userSchema.methods.comparePassword = function(password, done) {
  bcrypt.compare(password, this.password, function(err, isMatch) {
    done(err, isMatch);
  });
};

userSchema.methods.generateHash = function(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(SALT_FACTOR), null);
};

userSchema.methods.validPassword = function(password) {
  return bcrypt.compareSync(password, this.local.password);
};

userSchema.pre('save', function(next) {
  var user = this;
  if (!user.isModified('password')) {
    console.log('test');
    return next();
  }
  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    console.log('here');
    bcrypt.hash(user.local.password, salt, function(err, hash) {
      console.log('here2');
      user.local.password = hash;
      next();
    });
  });
});

module.exports = mongoose.model('User', userSchema);