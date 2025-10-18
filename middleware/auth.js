const jwt = require('jsonwebtoken');
const Servant = require('../models/Servant');

// Middleware to verify JWT token
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'رمز الوصول مطلوب'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const servant = await Servant.findById(decoded.id).select('-password');

    if (!servant || !servant.isActive) {
      return res.status(401).json({
        success: false,
        message: 'مستخدم غير صحيح أو غير نشط'
      });
    }

    req.user = servant;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: 'رمز غير صحيح'
    });
  }
};

// Middleware to check permissions
const checkPermission = (requiredPermissions) => {
  return (req, res, next) => {
    const user = req.user;

    // Super admin has all permissions
    if (user.role === 'super_admin') {
      return next();
    }

    // Check if user has required permissions
    const hasPermission = requiredPermissions.every(permission =>
      user.permissions.includes(permission)
    );

    if (!hasPermission) {
      return res.status(403).json({
        success: false,
        message: 'صلاحيات غير كافية'
      });
    }

    next();
  };
};

// Middleware to check gender access
const checkGenderAccess = (req, res, next) => {
  const user = req.user;
  const requestedGender = req.query.gender || req.body.gender;

  // Super admin has access to all genders
  if (user.role === 'super_admin') {
    return next();
  }

  // If no specific gender requested, check user's general access
  if (!requestedGender) {
    return next();
  }

  // Check if user can access the requested gender
  if (user.genderAccess === 'both' || user.genderAccess === requestedGender) {
    return next();
  }

  return res.status(403).json({
    success: false,
    message: 'تم رفض الوصول لبيانات هذا النوع'
  });
};

module.exports = {
  authenticateToken,
  checkPermission,
  checkGenderAccess
};
