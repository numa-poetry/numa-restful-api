'use strict';

var mongoose   = require('mongoose');
var timestamps = require('mongoose-timestamp');
var User       = require('./models/user.js');
var Comment    = require('./models/comment.js');
var Tag        = require('./models/tag.js');
var Schema     = mongoose.Schema;

// schema ----------------------------------------------------------------------
var poemSchema = new Schema({
  _creator    : { type: Schema.Types.ObjectId, ref: 'User' },
  title       : { type: String },
  tags        : [{ type: Schema.Types.ObjectId, ref: 'Tag' }],
  comments    : [{ type: Schema.Types.ObjectId, ref: 'Comment' }],
  upvotes     : { type: Number },
  downvotes   : { type: Number },
  inspiration : { type: String }
});

// plugins ---------------------------------------------------------------------
poemSchema.plugin(timestamps);

module.exports = mongoose.model('Poem', poemSchema);