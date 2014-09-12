'use strict';

var mongoose   = require('mongoose');
var timestamps = require('mongoose-timestamp');
var User       = require('./models/user.js');
var Poem       = require('./models/poem.js');
var Schema     = mongoose.Schema;

// schema ----------------------------------------------------------------------
var commentSchema = new Schema({
  _creator : { type: Schema.Types.ObjectId, ref: 'User' },
  poem     : { type: Schema.Types.ObjectId, ref: 'Poem' },
  comment  : { type: String }
});

// plugins ---------------------------------------------------------------------
commentSchema.plugin(timestamps);

module.exports = mongoose.model('Comment', commentSchema);