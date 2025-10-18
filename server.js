const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config({ path: './config.env' });

// Import routes
const authRoutes = require('./routes/auth');
const personRoutes = require('./routes/persons');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => {
    console.log('تم الاتصال بقاعدة البيانات MongoDB');

    // Create super admin if it doesn't exist
    createSuperAdmin();
  })
  .catch((error) => {
    console.error('خطأ في الاتصال بقاعدة البيانات MongoDB:', error);
    process.exit(1);
  });

// Create super admin function
const createSuperAdmin = async () => {
  try {
    const Servant = require('./models/Servant');
    const superAdmin = await Servant.findOne({ role: 'super_admin' });

    if (!superAdmin) {
      const newSuperAdmin = new Servant({
        username: process.env.SUPER_ADMIN_USERNAME,
        password: process.env.SUPER_ADMIN_PASSWORD,
        role: 'super_admin',
        permissions: ['view_boys', 'view_girls', 'edit_data', 'create_data', 'delete_data', 'manage_admins', 'manage_notes'],
        genderAccess: 'both'
      });

      await newSuperAdmin.save();
    }
  } catch (error) {
    console.error('خطأ في إنشاء المدير الرئيسي:', error);
  }
};

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/persons', personRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'نظام KAF يعمل بنجاح',
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    message: 'خطأ داخلي في الخادم'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'المسار غير موجود'
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`خادم نظام KAF يعمل على المنفذ ${PORT}`);
  console.log(`فحص الصحة: http://localhost:${PORT}/api/health`);
});
