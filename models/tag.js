'use strict';

var mongoose   = require('mongoose');
var timestamps = require('mongoose-timestamp');
var Poem       = require('./models/poem.js');
var Schema     = mongoose.Schema;

// schema ----------------------------------------------------------------------
var tagSchema = new Schema({
  tag  : { type: String, lowercase: true, trim: true },
  poem : { type: Schema.Types.ObjectId, ref: 'Poem' }
});

// plugins ---------------------------------------------------------------------
tagSchema.plugin(timestamps);

module.exports = mongoose.model('Tag', tagSchema);