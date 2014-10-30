module.exports = function(){
  var express = require('express');
  var app = express();

  app.get('/:id', function(req, res){...});

  return app;
}();