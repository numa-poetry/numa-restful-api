'use strict';

var message;

try {

// modules ---------------------------------------------------------------------
  var express      = require('express');
  var logger       = require('express-logger');
  var mongoose     = require('mongoose');
  var bodyParser   = require('body-parser');
  var cookieParser = require('cookie-parser');
  var errorhandler = require('errorhandler');
  var colors       = require('colors');
  var cors         = require('cors');
  var PrettyError  = require('pretty-error');
  var cool         = require('cool-ascii-faces');
  var superb       = require('superb');
  var auth         = require('./config/auth.js');
  var app          = express();

  var port         = process.env.PORT || 3000;

// db config -------------------------------------------------------------------
  mongoose.connect(auth.CONNECTION_URI);

  mongoose.connection.on('error', function() {
    message = '✗ MongoDB Connection Error. Please make sure MongoDB is running and restart the server.';
    console.error(message.red);
  });

// global config ---------------------------------------------------------------
  app.set('port', port);
  app.use(logger({
    path: './logfile.txt'
  }));
  app.use(cookieParser());
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({
    extended: true
  }));
  app.use(cors());

// env config ------------------------------------------------------------------
  if (app.get('env') === 'development') {
    message = 'Running in development mode';
    console.log(message.yellow);
    app.use(errorhandler());
    // mongoose.set('debug', true);
  }

  if (app.get('env') === 'production') {
    message = 'Running in production mode';
    console.log(message.yellow);

    // Force HTTPS
    // app.use(function(req, res, next) {
    //   var protocol = req.get('x-forwarded-proto');
    //   protocol == 'https' ? next() : res.redirect('https://' + req.hostname + req.url);
    // });
    app.use(errorhandler({
      dumpExceptions : true,
      showStack      : true
    }));
  }

// routes ----------------------------------------------------------------------
  require('./routes.js')(app);

// middleware ------------------------------------------------------------------
  var pe = new PrettyError();

  app.use(function(err, req, res, next) {
    // console.log(err.stack);
    console.log(pe.render(err));
    res.status(500).send({
      type    : 'internal_server_error',
      message : res.message
    });
  });

  // simplify stack trace
  pe.skipNodeFiles(); // this will skip events.js and http.js and similar core node files
  pe.skipPackage('express'); // this will skip all the trace lines about express' core and sub-modules

// run server ------------------------------------------------------------------
  app.listen(port, function() {
    message = '\n' + superb() + '! ' + cool().yellow + '\nThe express server is now ' +
      'listening on port ' + port + '.';
    console.log(message.bold.blue);
  });
}

// https://stackoverflow.com/questions/12890494/improving-express-js-module-usage
catch (exception) {
  var message = 'Server exception: ' + exception;
  console.log(message.bold.red);
}