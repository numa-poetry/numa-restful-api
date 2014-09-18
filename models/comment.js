'use strict';

var mongoose   = require('mongoose');
var timestamps = require('mongoose-timestamp');
var User       = require('./user.js');
var Poem       = require('./poem.js');
var Schema     = mongoose.Schema;

// schema ----------------------------------------------------------------------
var commentSchema = new Schema({
  creator  : { type: Schema.Types.ObjectId, ref: 'User' },
  poem     : { type: Schema.Types.ObjectId, ref: 'Poem' },
  comment  : { type: String }
});

// plugins ---------------------------------------------------------------------
commentSchema.plugin(timestamps);

module.exports = mongoose.model('Comment', commentSchema);