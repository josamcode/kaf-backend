const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const Servant = require('../models/Servant');
const { authenticateToken, checkPermission } = require('../middleware/auth');
const { authRateLimiter } = require('../middleware/security');
const asyncHandler = require('../utils/asyncHandler');
const cache = require('../utils/cache');

const router = express.Router();

const ADMIN_CACHE_PREFIX = 'admins:';
const VALID_PERMISSIONS = new Set([
  'view_boys',
  'view_girls',
  'edit_data',
  'create_data',
  'delete_data',
  'manage_admins',
  'manage_notes'
]);

const validate = (rules) => [
  ...rules,
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'أخطاء في التحقق من البيانات',
        errors: errors.array()
      });
    }
    return next();
  }
];

const validatePermissions = body('permissions')
  .isArray()
  .withMessage('الصلاحيات يجب أن تكون مصفوفة')
  .custom((permissions) => permissions.every((permission) => VALID_PERMISSIONS.has(permission)))
  .withMessage('الصلاحيات يجب أن تكون مصفوفة');

// Generate JWT token
const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });

// @route   POST /api/auth/login
// @desc    Login servant
// @access  Public
router.post('/login', [
  authRateLimiter,
  ...validate([
    body('username')
      .trim()
      .notEmpty()
      .withMessage('اسم المستخدم مطلوب'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
  ])
], asyncHandler(async (req, res) => {
  const { username, password } = req.body;

  // Find servant by username
  const servant = await Servant.findOne({ username, isActive: true })
    .select('username password role permissions genderAccess');

  if (!servant) {
    return res.status(401).json({
      success: false,
      message: 'بيانات الدخول غير صحيحة'
    });
  }

  // Check password
  const isPasswordValid = await servant.comparePassword(password);
  if (!isPasswordValid) {
    return res.status(401).json({
      success: false,
      message: 'بيانات الدخول غير صحيحة'
    });
  }

  // Generate token
  const token = generateToken(servant._id);

  // Return user data (without password) and token
  const userData = {
    id: servant._id,
    username: servant.username,
    role: servant.role,
    permissions: servant.permissions,
    genderAccess: servant.genderAccess
  };

  return res.json({
    success: true,
    message: 'تم تسجيل الدخول بنجاح',
    token,
    user: userData
  });
}));

// @route   GET /api/auth/me
// @desc    Get current user info
// @access  Private
router.get('/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      username: req.user.username,
      role: req.user.role,
      permissions: req.user.permissions,
      genderAccess: req.user.genderAccess
    }
  });
});

// @route   POST /api/auth/create-admin
// @desc    Create new admin (super admin only)
// @access  Private (Super Admin)
router.post('/create-admin', [
  authenticateToken,
  checkPermission(['manage_admins']),
  ...validate([
    body('username')
      .trim()
      .notEmpty()
      .withMessage('اسم المستخدم مطلوب'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل'),
    validatePermissions,
    body('genderAccess')
      .isIn(['boys', 'girls', 'both'])
      .withMessage('صلاحية الوصول للنوع غير صحيحة')
  ])
], asyncHandler(async (req, res) => {
  const { username, password, permissions, genderAccess } = req.body;

  // Check if username already exists
  const existingServant = await Servant.findOne({ username }).select('_id').lean();
  if (existingServant) {
    return res.status(400).json({
      success: false,
      message: 'اسم المستخدم موجود بالفعل'
    });
  }

  // Create new servant
  const newServant = new Servant({
    username,
    password,
    permissions,
    genderAccess,
    createdBy: req.user._id
  });

  await newServant.save();
  cache.delByPrefix(ADMIN_CACHE_PREFIX);

  return res.status(201).json({
    success: true,
    message: 'تم إنشاء المدير بنجاح',
    admin: {
      id: newServant._id,
      username: newServant.username,
      role: newServant.role,
      permissions: newServant.permissions,
      genderAccess: newServant.genderAccess
    }
  });
}));

// @route   GET /api/auth/admins
// @desc    Get all admins (super admin only)
// @access  Private (Super Admin)
router.get('/admins', [
  authenticateToken,
  checkPermission(['manage_admins'])
], asyncHandler(async (req, res) => {
  const cacheKey = `${ADMIN_CACHE_PREFIX}${req.user._id.toString()}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const admins = await Servant.find({ isActive: true })
    .select('username role permissions genderAccess createdAt createdBy')
    .populate('createdBy', 'username')
    .sort({ createdAt: -1 })
    .lean();

  // Transform _id to id for frontend compatibility
  const transformedAdmins = admins.map((admin) => ({
    id: admin._id,
    username: admin.username,
    role: admin.role,
    permissions: admin.permissions,
    genderAccess: admin.genderAccess,
    createdAt: admin.createdAt,
    createdBy: admin.createdBy
  }));

  const payload = {
    success: true,
    admins: transformedAdmins
  };

  cache.set(cacheKey, payload, 30 * 1000);
  return res.json(payload);
}));

// @route   PUT /api/auth/admins/:id
// @desc    Update admin permissions
// @access  Private (Super Admin)
router.put('/admins/:id', [
  authenticateToken,
  checkPermission(['manage_admins']),
  ...validate([
    validatePermissions,
    body('genderAccess')
      .isIn(['boys', 'girls', 'both'])
      .withMessage('صلاحية الوصول للنوع غير صحيحة')
  ])
], asyncHandler(async (req, res) => {
  const { permissions, genderAccess } = req.body;
  const adminId = req.params.id;

  // Validate adminId
  if (!adminId || adminId === 'undefined') {
    return res.status(400).json({
      success: false,
      message: 'معرف المدير غير صحيح'
    });
  }

  // Don't allow updating super admin
  const admin = await Servant.findById(adminId);
  if (!admin || admin.role === 'super_admin') {
    return res.status(400).json({
      success: false,
      message: 'لا يمكن تعديل المدير الرئيسي'
    });
  }

  admin.permissions = permissions;
  admin.genderAccess = genderAccess;
  await admin.save();
  cache.delByPrefix(ADMIN_CACHE_PREFIX);

  return res.json({
    success: true,
    message: 'تم تحديث المدير بنجاح',
    admin: {
      id: admin._id,
      username: admin.username,
      role: admin.role,
      permissions: admin.permissions,
      genderAccess: admin.genderAccess
    }
  });
}));

// @route   DELETE /api/auth/admins/:id
// @desc    Delete admin (soft delete)
// @access  Private (Super Admin)
router.delete('/admins/:id', [
  authenticateToken,
  checkPermission(['manage_admins'])
], asyncHandler(async (req, res) => {
  const adminId = req.params.id;

  // Validate adminId
  if (!adminId || adminId === 'undefined') {
    return res.status(400).json({
      success: false,
      message: 'معرف المدير غير صحيح'
    });
  }

  // Don't allow deleting super admin
  const admin = await Servant.findById(adminId);
  if (!admin || admin.role === 'super_admin') {
    return res.status(400).json({
      success: false,
      message: 'لا يمكن حذف المدير الرئيسي'
    });
  }

  admin.isActive = false;
  await admin.save();
  cache.delByPrefix(ADMIN_CACHE_PREFIX);

  return res.json({
    success: true,
    message: 'تم حذف المدير بنجاح'
  });
}));

module.exports = router;
