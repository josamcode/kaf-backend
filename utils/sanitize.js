const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

const escapeRegExp = (value = '') => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const normalizeGender = (value) => {
  if (!value || typeof value !== 'string') {
    return null;
  }

  const normalized = value.toLowerCase().trim();
  if (normalized === 'boy' || normalized === 'boys') return 'boy';
  if (normalized === 'girl' || normalized === 'girls') return 'girl';
  if (normalized === 'both') return 'both';
  return null;
};

const sanitizeValue = (value) => {
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }

  if (!value || typeof value !== 'object') {
    return value;
  }

  const sanitized = {};
  for (const [key, nestedValue] of Object.entries(value)) {
    if (DANGEROUS_KEYS.has(key) || key.startsWith('$') || key.includes('.')) {
      continue;
    }
    sanitized[key] = sanitizeValue(nestedValue);
  }
  return sanitized;
};

const sanitizeRequest = (req, _res, next) => {
  if (req.body) req.body = sanitizeValue(req.body);
  if (req.query) req.query = sanitizeValue(req.query);
  if (req.params) req.params = sanitizeValue(req.params);
  next();
};

module.exports = {
  escapeRegExp,
  normalizeGender,
  sanitizeRequest
};
