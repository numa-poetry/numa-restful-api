'use strict';

var mongoose           = require('mongoose');
var bcrypt             = require('bcrypt-nodejs');
var timestamps         = require('mongoose-timestamp');
var Poem               = require('./poem.js');
var Comment            = require('./comment.js');
var Schema             = mongoose.Schema;
var SALT_WORK_FACTOR   = 10;
var MAX_LOGIN_ATTEMPTS = 5;
var LOCK_TIME          = 60 * 60 * 1000; // 1 hour lock (ms)

// schema ----------------------------------------------------------------------
var userSchema = new Schema({
  github               : { type: String },
  google               : { type: String },
  facebook             : { type: String },

  displayName          : { type: String },
  email                : { type: String, trim: true },
  password             : { type: String },
  avatarUrl            : { type: String },

  local                : { displayName: { type: String, unique: true, sparse: true, trim: true } },

  loginAttempts        : { type: Number, required: true, default: 0 },
  lockUntil            : { type: Number },

  resetPasswordToken   : { type: String },
  resetPasswordExpires : { type: Date },

  poems                : [{ type: Schema.Types.ObjectId, ref: 'Poem' }],
  favoritePoems        : [{ type: Schema.Types.ObjectId, ref: 'Poem' }],
  unreadFollowingPoems : [{ type: Schema.Types.ObjectId, ref: 'Poem' }],
  comments             : [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
  unreadComments       : [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
  followers            : [{ type: Schema.Types.ObjectId, ref: 'User' }],
  following            : [{ type: Schema.Types.ObjectId, ref: 'User' }]
});

userSchema.virtual('isLocked').get(function() {
  // check for a future lockUntil timestamp
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// plugins ---------------------------------------------------------------------
userSchema.plugin(timestamps);

// methods ---------------------------------------------------------------------
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) {
      return cb(err);
    }
    cb(null, isMatch);
  });
};

userSchema.methods.generateHash = function(password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(SALT_WORK_FACTOR), null);
};

// userSchema.pre('save', function(next) {
//   var user = this;

//   // only hash the password if it has been modified (or is new)
//   if (!user.isModified('local.password')) return next();

//   // generate a salt
//   bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
//     if (err) return next(err);

//     // hash the password using our new salt
//     bcrypt.hash(user.local.password, salt, null, function(err, hash) {
//       if (err) return next(err);

//       // override the cleartext password with the hashed one
//       user.local.password = hash;
//       next();
//     });
//   });
// });

userSchema.methods.validPassword = function(password) {
  return bcrypt.compareSync(password, this.password);
};

userSchema.methods.incLoginAttempts = function(cb) {
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

// Sanitize
// userSchema.methods.toJSON = function() {
//   var user = this.toObject();
//   delete user._id;
//   delete user.__v;
//   delete user.email;
//   delete user.password;
//   delete user.updatedAt;
//   return user;
// };

// statics ---------------------------------------------------------------------
// Expose enum on the model, and provide an internal convenience reference
var reasons = userSchema.statics.failedLogin = {
  NOT_FOUND          : 0,
  PASSWORD_INCORRECT : 1,
  MAX_ATTEMPTS       : 2
};

userSchema.statics.getAuthenticated = function(displayName, password, cb) {

  this.findOne({
    'local.displayName': displayName
  }, function(err, user) {
    if (err) {
      return cb(err);
    }

    // make sure user exists
    if (!user) {
      return cb(null, null, reasons.NOT_FOUND);
    }

    // check if the account is currently locked
    if (user.isLocked) {
      // just increment login attempts if account is already locked
      return user.incLoginAttempts(function(err) {
        if (err) {
          return cb(err);
        }
        return cb(null, null, reasons.MAX_ATTEMPTS);
      });
    }

    // test for a matching password
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return cb(err);
      }

      // check if the password was a match
      if (isMatch) {
        // if there's no lock or failed attempts, just return the user
        if (!user.loginAttempts && !user.lockUntil) {
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
          return cb(err);
        }
        return cb(null, null, reasons.PASSWORD_INCORRECT);
      });
    });
  });
};

module.exports = mongoose.model('User', userSchema);