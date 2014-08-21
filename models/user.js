'use strict';

var mongoose           = require('mongoose');
var Schema             = mongoose.Schema;
var bcrypt             = require('bcrypt-nodejs');
var timestamps         = require('mongoose-timestamp');
var SALT_WORK_FACTOR   = 10;
var MAX_LOGIN_ATTEMPTS = 5;
var LOCK_TIME          = 2 * 60 * 60 * 1000; // 2 hour lock
/**
 * User Schema
 */
var UserSchema = new Schema({

  local: {
    username: { type: String, required: true, index: { unique: true } },
    email: { type: String },
    password: { type: String, required: true }
  },
  loginAttempts: { type: Number, required: true, default: 0 },
  lockUntil: { type: Number }

});

/**
 * Virtuals
 */
UserSchema.virtual('isLocked').get(function() {
  // check for a future lockUntil timestamp
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

/**
 * Plugins
 */
UserSchema.plugin(timestamps);

/**
 * Methods
 */
UserSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.local.password, function(err, isMatch) {
    if (err) {
      return cb(err);
    }
    cb(null, isMatch);
  });
};

UserSchema.methods.generateHash = function(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(SALT_WORK_FACTOR), null);
};

UserSchema.methods.validPassword = function(password) {
  return bcrypt.compareSync(password, this.local.password);
};

UserSchema.methods.incLoginAttempts = function(cb) {
  // if we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.update({
      $set: { loginAttempts: 1 },
      $unset: { lockUntil: 1 }
    }, cb);
  }
  
  // otherwise we're incrementing
  var updates = { $inc: { loginAttempts: 1 } };

  // lock the account if we've reached max attempts and it's not locked already
  if (this.loginAttempts + 1 >= MAX_LOGIN_ATTEMPTS && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + LOCK_TIME };
  }
  return this.update(updates, cb);
};

/**
 * Overrides
 */
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
 * Statics
 */

// Expose enum on the model, and provide an internal convenience reference
var reasons = UserSchema.statics.failedLogin = {
  NOT_FOUND: 0,
  PASSWORD_INCORRECT: 1,
  MAX_ATTEMPTS: 2
};

UserSchema.statics.getAuthenticated = function(username, password, cb) {
  
  // console.log('username:', username);
  // console.log('password:', password);

  this.findOne({
    'local.username': username
  }, function(err, user) {
    if (err) {
      // console.log('1')
      return cb(err);
    }

    // make sure user exists
    if (!user) {
      // console.log('2');
      return cb(null, null, reasons.NOT_FOUND);
    }

    // check if the account is currently locked
    if (user.isLocked) {
      // console.log('3');
      // just increment login attempts if account is already locked
      return user.incLoginAttempts(function(err) {
        if (err) {
          // console.log('4')
          return cb(err);
        }
        // console.log('5')
        return cb(null, null, reasons.MAX_ATTEMPTS);
      });
    }

    // test for a matching password
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        // console.log('6')
        return cb(err);
      }

      // check if the password was a match
      if (isMatch) {
        // console.log('7')
        // if there's no lock or failed attempts, just return the user
        if (!user.loginAttempts && !user.lockUntil) {
          // console.log('8')
          return cb(null, user);
        }

        // reset attempts and lock info
        var updates = {
          $set: { loginAttempts: 0 },
          $unset: { lockUntil: 1 }
        };
        return user.update(updates, function(err) {
          if (err) {
            return cb(err);
          }
          return cb(null, user);
        });
      }

      // password is incorrect, so increment login attempts before responding
      user.incLoginAttempts(function(err) {
        if (err) {
          // console.log('9')
          return cb(err);
        }
        // console.log('10')
        return cb(null, null, reasons.PASSWORD_INCORRECT);
      });
    });
  });
};

/**
 * Middleware
 */
// UserSchema.pre('save', function(next) {
//   var user = this;

//   if (!user.isModified('password')) {
//     return next();
//   }
//   bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
//     bcrypt.hash(user.local.password, salt, function(err, hash) {
//       user.local.password = hash;
//       next();
//     });
//   });
// });

module.exports = mongoose.model('User', UserSchema);