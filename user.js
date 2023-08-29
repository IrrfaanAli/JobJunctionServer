const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: String,
  password: String, // Store hashed password
  lastLogin: Date,
  loginAttempts: Number,
  isLocked: Boolean,
  lockUntil: Date,
});

module.exports = mongoose.model('User', userSchema);