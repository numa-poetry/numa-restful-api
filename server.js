'use strict';

try {

// modules ---------------------------------------------------------------------
  var express         = require('express');
  var logger          = require('express-logger');
  var passport        = require('passport');
  var mongoose        = require('mongoose');
  var bodyParser      = require('body-parser');
  var cookieParser    = require('cookie-parser');
  var session         = require('express-session');
  var errorhandler    = require('errorhandler');
  var colors          = require('colors');
  var cors            = require('cors');
  var app             = express();
  var db              = require('./config/db.js');

// global config ---------------------------------------------------------------
  app.set('port', process.env.PORT || 3000);
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(logger({
    path: './logfile.txt'
  }));
  app.use(cookieParser());
  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(bodyParser.json())
  app.use(session({
    secret            : 'auth-demo',
    saveUninitialized : true,
    resave            : true
  }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(cors());

// env config ------------------------------------------------------------------
  if (process.env.NODE_ENV === 'development') {
    app.use(errorhandler());
  }

  if (process.env.NODE_ENV === 'production') {
    app.use(errorhandler({
      dumpExceptions : true,
      showStack      : true
    }));
  }

// passport config -------------------------------------------------------------
  require('./passport.js')(passport);

// db config -------------------------------------------------------------------
  mongoose.connect(db.CONNECTION_URI);

// routes ----------------------------------------------------------------------
  require('./routes.js')(app, passport);

// run server ------------------------------------------------------------------
  app.listen(app.get('port'), function() {
    var message = '\nExpress server listening on port ' + app.get('port');
    console.log(message.bold.blue);
  });
}

// https://stackoverflow.com/questions/12890494/improving-express-js-module-usage
catch (exception) {
  var message = 'Server exception: ' + exception;
  console.log(message.bold.red);
}