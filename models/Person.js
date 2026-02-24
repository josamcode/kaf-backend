const mongoose = require('mongoose');

const personSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  gender: {
    type: String,
    enum: ['boy', 'girl'],
    required: true
  },
  birthDate: {
    type: Date
  },
  college: {
    type: String,
    trim: true,
    maxlength: 100
  },
  university: {
    type: String,
    trim: true,
    maxlength: 100
  },
  residence: {
    type: String,
    trim: true,
    maxlength: 200
  },
  origin: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  year: {
    type: Number,
    enum: [1, 2, 3, 4, 5],
    required: true
  },
  phone: {  
    type: String,
    required: true,
    trim: true,
    validate: {
      validator: function (v) {
        return /^[0-9+\-\s()]+$/.test(v);
      },
      message: 'Phone number format is invalid'
    }
  },
  customFields: {
    type: Map,
    of: String
  },
  notes: [{
    content: {
      type: String,
      required: true,
      trim: true,
      maxlength: 500
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Servant',
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }],
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Servant',
    required: true
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Index for better query performance
personSchema.index({ gender: 1, year: 1 });
personSchema.index({ origin: 1 });
personSchema.index({ createdBy: 1 });
personSchema.index({ isActive: 1, createdAt: -1 });
personSchema.index({ isActive: 1, gender: 1, createdAt: -1 });
personSchema.index({ isActive: 1, gender: 1, year: 1 });

module.exports = mongoose.model('Person', personSchema);
