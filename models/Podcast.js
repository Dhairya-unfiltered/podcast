const mongoose = require('mongoose');

const podcastSchema = new mongoose.Schema({
  name: String,
  url: String,
  cloudinaryId: String,
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Podcast', podcastSchema);
