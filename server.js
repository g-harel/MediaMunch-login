const mongoose = require('mongoose');
const cryptojs = require('crypto-js');
const SHA256 = cryptojs.SHA256;

const express = require('express');
const app = express();

// connect to mongo
mongoose.connect('mongodb://localhost/test', (err) => {
  if (err) {
    console.log('could not connect to database');
  }
});

// define user schema
const UserSchema = mongoose.Schema({
  email: {
    type: String,
    validate: {
      validator: (val) => {
        var emailPattern = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        return emailPattern.test(val);
      },
      message: '"{VALUE}" is not a valid email address',
    },
    required: [true, 'Email address not provided'],
    unique: [true, 'Duplicate email not allowed'],
  },
  username: {
    type: String,
    validate: {
      validator: (val) => {
        var usernamePattern = /\w{3,20}/;
        return usernamePattern.test(val);
      },
      message: '"{VALUE}" is not a valid username',
    },
    unique: [true, 'Duplicate usernames not allowed'],
  },
  dateCreated: {
    type: String,
    default: Date.now(),
  },
  dateUpdated: {
    type: String,
    default: Date.now(),
  },
  pass: {
    type: String,
    required: [true, 'Password not provided'],
  }
});

// hash password when saving to db
UserSchema.pre('save', function(next) {
  var user = this;
  user.dateUpdated = Date.now();
  if (user.isModified('pass')) {
    user.pass = hash_password(user);
  }
  next();
});

// create a user model based on schema
const UserModel = mongoose.model('User', UserSchema);

// generate pass hash
function hash_password(user) {
  return SHA256(user.pass + user.username + user.dateCreated + 'MediaMunch').toString();
}

// add a new user
function addUser(user, callback) {
  UserModel.create({
    email: user.email,
    username: user.username,
    pass: user.pass,
  }, (err, user) => {
    if (err) {
      console.log(err);
      callback(':: error adding user to db', null);
    } else {
      callback(null, user);
    }
  });
}

// updates user
function updateUser(username, property, newValue, callback) {
  UserModel.find({ username: username }, (err, res) => {
    if (err) {
      callback(':: error querying db', null);
    } else {
      if (res.length !== 1) {
        callback(':: username not found', null);
      } else {
        res[0][property] = newValue;
        res[0].save((err, updatedUser) => {
          if (err) {
            callback(':: error when updating db', null);
          } else {
            callback(null, updatedUser);
          }
        });
      }
    }
  });
}

// verifies that the password matches
function authenticate(property, value, pass, callback) {
  const search = {};
  search[property] = value;
  UserModel.find(search, (err, res) => {
    if (err) {
      callback(':: error when querying db', null);
    } else {
      if (res.length !== 1) {
        callback(':: user not found', null);
      } else {
        if (res[0].pass === hash_password({
            pass: pass,
            username: res[0].username,
            dateCreated: res[0].dateCreated,
          })) {
          callback(null, res[0]);
        } else {
          callback(':: pass does not match', null);
        }
      }
    }
  });
}

// print all users
function getAllUsers(callback) {
  UserModel.find({}, (err, res) => {
    if (err) {
      console.log(':: error querying database');
    } else {
      if (callback) {
        callback(res);
      }
    }
  });
}

// login request
app.get('/auth', (req, res) => {
  authenticate('username', req.query.username, req.query.pass, (err, user) => {
    res.send(err || JSON.stringify(user));
  });
});

// user create request
app.get('/create', (req, res) => {
  addUser({
    username: req.query.username,
    email: req.query.email,
    pass: req.query.pass,
  }, (err, user) => {
    res.send(err || JSON.stringify(user));
  })
});

// request for all users
app.get('/users', (req, res) => {
  getAllUsers((err, users) => {
    res.send(err || JSON.stringify(users))
  });
});

// specific user request
app.get('/user/:username', (req, res) => {
  UserModel.find({ username: req.params.username }, (err, _res) => {
    res.send(err || JSON.stringify(_res[0]));
  });
});

app.listen(44, () => {
  console.log('listening to port 44');
});
