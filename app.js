var express = require('express');
var path = require('path');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');

mongoose.connect('localhost');
var app = express();

var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

userSchema.pre('save', function (next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function (err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function (err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function (candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

var User = mongoose.model('User', userSchema);

passport.use(new LocalStrategy((username, password, done) => {
  User.findOne({ username }).then((user) => {
    if (!user) {
      return done(null, false, { message: 'REMOVE THIS: Incrrect username' });
    }
    user.comparePassword(password, (err, isMatch) => {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password' });
      }
    })
  }).catch((err) => {
    return done(err);
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

// Middleware
app.set('port', process.env.PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(flash());
app.use(cookieParser());
app.use(session({ secret: 'session secret key' }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));



// Routes
app.get('/', (req, res) => {
  res.render('index', {
    title: 'Password Reset',
    user: req.user
  });
});

app.get('/login', (req, res) => {
  res.render('login', {
    user: req.user
  });
});

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.redirect('/login')
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect('/')
    });
  })(req, res, next);
});


app.get('/signup', (req, res) => {
  res.render('signup', {
    user: req.user
  });
});

app.post('/signup', (req, res) => {
  var user = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password
  });

  user.save().then(() => {
    req.logIn(user, (err) => {
      res.redirect('/');
    });
  });
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/forgot', (req, res) => {
  res.render('forgot', {
    user: req.user
  });
});

app.post('/forgot', (req, res) => {

  async.waterfall([
    (done) => {
      crypto.randomBytes(20, (err, buf) => {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    (token, done) => {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.')
          return res.redirect('/forgot');
        }
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save((err) => {
          done(err, token, user);
        });
      });
    },
    (token, user, done) => {
      let poolConfig = {
        pool: true,
        host: 'smtp.zoho.com',
        port: 465,
        secure: true, // use TLS
        auth: {
          user: 'adam@adamth.com',
          pass: 'rj2jGcme3CQW'
        }
      };
      var smtpTransport = nodemailer.createTransport(poolConfig);
      let mailOptions = {
          from: '"Password reset" <noreply@adamth.com>', // sender address
          to: user.email, // list of receivers
          subject: 'Node.js Password Reset', // Subject line
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions,(err,info) => {
        console.log(info)
        req.flash('info', `An email has been sent to ${user.email} with further instructions.`);
        done(err, 'done');
      });
    }
  ],(err) => {
    if(err) return next(err);
    res.redirect('/forgot');
  });
});

app.post('/reset/:token', (req, res) => {
  async.waterfall([
    (done) => {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
        if(!user) {
          req.flash('error', 'Password reset token is invalid or expired.');
          return res.redirect('/forgot');
        }
        
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save((err) => {
          req.logIn(user, (err) => {
            done(err, user);
          });
        });
      });
    },
    (user, done) => {
      let poolConfig = {
        pool: true,
        host: 'smtp.zoho.com',
        port: 465,
        secure: true, // use TLS
        auth: {
          user: 'adam@adamth.com',
          pass: 'rj2jGcme3CQW'
        }
      };
      var smtpTransport = nodemailer.createTransport(poolConfig);
      let mailOptions = {
          from: '"Password reset" <noreply@adamth.com>', // sender address
          to: user.email, // list of receivers
          subject: 'Your password has been changed.', // Subject line
          text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions,(err,info) => {
        console.log(info)
        req.flash('info', `An email has been sent to ${user.email} with further instructions.`);
        done(err, 'done');
      });
    }
  ], (err) => {
    res.redirect('/');
  });
});

app.get('/reset/:token', (req, res) => {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

app.listen(app.get('port'), function () {
  console.log('Express server listening on port ' + app.get('port'));
});