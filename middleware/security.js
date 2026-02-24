const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { sanitizeRequest } = require('../utils/sanitize');

const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX || 1000),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'عدد الطلبات كبير جدًا، يرجى المحاولة مرة أخرى لاحقًا'
  },
  skip: (req) => req.path === '/api/health'
});

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'عدد محاولات تسجيل الدخول كبير جدًا، يرجى المحاولة مرة أخرى لاحقًا'
  }
});

const securityMiddleware = [
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  }),
  sanitizeRequest
];

module.exports = {
  securityMiddleware,
  apiRateLimiter,
  authRateLimiter
};