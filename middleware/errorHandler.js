const AppError = require('../utils/appError');

const notFoundHandler = (_req, res) => {
  res.status(404).json({
    success: false,
    message: 'المسار غير موجود'
  });
};

const errorHandler = (err, req, res, _next) => {
  const defaultMessage = req.originalUrl && req.originalUrl.startsWith('/api/auth')
    ? 'خطأ في الخادم'
    : 'Server error';

  if (err instanceof AppError) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message
    });
  }

  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation errors',
      errors: Object.values(err.errors).map((error) => ({
        msg: error.message,
        path: error.path
      }))
    });
  }

  if (err.name === 'CastError') {
    return res.status(500).json({
      success: false,
      message: defaultMessage
    });
  }

  if (process.env.NODE_ENV !== 'production') {
    console.error('Error:', err);
  } else {
    console.error('Error:', err.message);
  }

  return res.status(500).json({
    success: false,
    message: defaultMessage
  });
};

module.exports = {
  errorHandler,
  notFoundHandler
};
