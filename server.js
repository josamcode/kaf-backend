const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const compression = require('compression');
require('dotenv').config({ path: './config.env' });

// Import routes
const authRoutes = require('./routes/auth');
const personRoutes = require('./routes/persons');
const Servant = require('./models/Servant');
const { securityMiddleware, apiRateLimiter } = require('./middleware/security');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

if (!process.env.MONGODB_URI) {
  throw new Error('MONGODB_URI is required');
}

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is required');
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const corsOrigin = process.env.CORS_ORIGIN;
const corsOptions = corsOrigin
  ? {
      origin: corsOrigin.split(',').map((origin) => origin.trim()),
      credentials: true
    }
  : {};

// Middleware
app.use(cors(corsOptions));
app.use(...securityMiddleware);
app.use(compression());
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));
app.use(apiRateLimiter);

mongoose.set('strictQuery', true);
mongoose.set('sanitizeFilter', true);

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  maxPoolSize: Number(process.env.MONGODB_MAX_POOL_SIZE || 20),
  minPoolSize: Number(process.env.MONGODB_MIN_POOL_SIZE || 2),
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000
})
  .then(async () => {
    console.log('تم الاتصال بقاعدة البيانات MongoDB');
    await createSuperAdmin();
  })
  .catch((error) => {
    console.error('خطأ في الاتصال بقاعدة البيانات MongoDB:', error.message);
    process.exit(1);
  });

// Create super admin function
const createSuperAdmin = async () => {
  try {
    const superAdmin = await Servant.findOne({ role: 'super_admin' }).select('_id').lean();
    if (superAdmin) {
      return;
    }

    if (!process.env.SUPER_ADMIN_USERNAME || !process.env.SUPER_ADMIN_PASSWORD) {
      return;
    }

    const newSuperAdmin = new Servant({
      username: process.env.SUPER_ADMIN_USERNAME,
      password: process.env.SUPER_ADMIN_PASSWORD,
      role: 'super_admin',
      permissions: [
        'view_boys',
        'view_girls',
        'edit_data',
        'create_data',
        'delete_data',
        'manage_admins',
        'manage_notes'
      ],
      genderAccess: 'both'
    });

    await newSuperAdmin.save();
  } catch (error) {
    console.error('خطأ في إنشاء المدير الرئيسي:', error.message);
  }
};

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/persons', personRoutes);

// Health check endpoint
app.get('/api/health', (_req, res) => {
  res.json({
    success: true,
    message: 'نظام KAF يعمل بنجاح',
    timestamp: new Date().toISOString()
  });
});

app.use(notFoundHandler);
app.use(errorHandler);

const PORT = process.env.PORT || 5000;
const server = app.listen(PORT, () => {
  console.log(`خادم نظام KAF يعمل على المنفذ ${PORT}`);
  if (process.env.NODE_ENV !== 'production') {
    console.log(`فحص الصحة: http://localhost:${PORT}/api/health`);
  }
});

const gracefulShutdown = async () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
