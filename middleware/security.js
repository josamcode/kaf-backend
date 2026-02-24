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
    message: 'Too many requests, please try again later'
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
    message: 'Too many login attempts, please try again later'
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
