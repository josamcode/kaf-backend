const mongoose = require('mongoose');

const servantSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['super_admin', 'admin'],
    default: 'admin'
  },
  permissions: [{
    type: String,
    enum: ['view_boys', 'view_girls', 'edit_data', 'create_data', 'delete_data', 'manage_admins', 'manage_notes']
  }],
  genderAccess: {
    type: String,
    enum: ['boys', 'girls', 'both'],
    default: 'both'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Servant'
  }
}, {
  timestamps: true
});

// Hash password before saving
servantSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  const bcrypt = require('bcryptjs');
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
servantSchema.methods.comparePassword = async function (candidatePassword) {
  const bcrypt = require('bcryptjs');
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('Servant', servantSchema);
