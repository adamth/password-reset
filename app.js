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

mongoose.connect('localhost');
var app = express();

var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

userSchema.pre('save', function(next) {
  const user = this;
  const SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR,(err, salt) => {
    if(err) return next(err);

    bcrypt.hash(user.password, salt, (err, hash) => {
      if(err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, (err, result) => {
    if(err) return cb(err);
    cb(null, result);
  });
};

var User = mongoose.model('User', userSchema);

passport.use(new LocalStrategy((username, password, done) => {
  User.findOne({ username }).then((user) => {
    if (!user){
      return done(null, false, {message: 'REMOVE THIS: Incrrect username'});
    }
    user.comparePassword(password, (err, isMatch) => {
      if(isMatch) {
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

app.get('/signup', (req,res) => {
  res.render('signup', {
    user: req.user
  });
})

app.post('/login', (req,res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if(err) return next(err);
    if(!user) {
      return res.redirect('/login')
    }
    req.logIn(user, (err) => {
      if(err) return next(err);
      return res.redirect('/')
    })
  })(req, res, next);
})

app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});