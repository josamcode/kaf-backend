const express = require('express');
const { body, query, validationResult } = require('express-validator');
const Person = require('../models/Person');
const { authenticateToken, checkPermission, checkGenderAccess } = require('../middleware/auth');
const asyncHandler = require('../utils/asyncHandler');
const cache = require('../utils/cache');
const {
  escapeRegExp,
  normalizeGender,
  normalizeOrigin,
  sanitizeOriginValues,
  buildExactOriginRegex
} = require('../utils/sanitize');

const router = express.Router();

const STATS_CACHE_PREFIX = 'persons:stats:';
const PERSONS_CACHE_PREFIX = 'persons:list:';
const FORM_OPTIONS_CACHE_PREFIX = 'persons:form-options:';
const PERSON_WRITE_CACHE_PREFIXES = [STATS_CACHE_PREFIX, PERSONS_CACHE_PREFIX, FORM_OPTIONS_CACHE_PREFIX];
const PERSON_MUTABLE_FIELDS = new Set([
  'name',
  'gender',
  'birthDate',
  'college',
  'university',
  'residence',
  'origin',
  'year',
  'phone',
  'customFields'
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

const clearPersonCaches = () => {
  for (const prefix of PERSON_WRITE_CACHE_PREFIXES) {
    cache.delByPrefix(prefix);
  }
};

const userAccessibleGender = (user) => {
  if (user.role === 'super_admin') return 'both';
  return normalizeGender(user.genderAccess) || 'both';
};

const hasGenderAccess = (user, personGender) => {
  const accessibleGender = userAccessibleGender(user);
  return accessibleGender === 'both' || accessibleGender === personGender;
};

const userAccessibleOrigins = (user) => {
  if (user.role === 'super_admin') return [];
  return sanitizeOriginValues(user.allowedOrigins);
};

const hasOriginAccess = (user, personOrigin) => {
  if (user.role === 'super_admin') return true;
  const allowedOrigins = userAccessibleOrigins(user);
  if (allowedOrigins.length === 0) return true;

  const targetOrigin = normalizeOrigin(personOrigin);
  return allowedOrigins.some((origin) => normalizeOrigin(origin) === targetOrigin);
};

const appendOriginAccessToFilter = (filter, user) => {
  if (user.role === 'super_admin') return filter;

  const allowedOrigins = userAccessibleOrigins(user);
  if (allowedOrigins.length === 0) return filter;

  const allowedOriginClause = allowedOrigins.length === 1
    ? { origin: buildExactOriginRegex(allowedOrigins[0]) }
    : {
      $or: allowedOrigins.map((origin) => ({
        origin: buildExactOriginRegex(origin)
      }))
    };

  if (!filter.$and) {
    filter.$and = [];
  }
  filter.$and.push(allowedOriginClause);
  return filter;
};

const parsePagination = (page, limit) => {
  const parsedPage = Number.parseInt(page, 10);
  const parsedLimit = Number.parseInt(limit, 10);

  return {
    page: Number.isInteger(parsedPage) && parsedPage > 0 ? parsedPage : 1,
    limit: Number.isInteger(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 200) : 50
  };
};

const normalizeOptionValues = (values) => {
  return [...new Set(
    (values || [])
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  )].sort((a, b) => a.localeCompare(b, 'ar', { sensitivity: 'base' }));
};

const buildFormOptionsMatch = (user) => {
  const filter = { isActive: true };
  if (user.role !== 'super_admin') {
    const access = userAccessibleGender(user);
    if (access !== 'both') {
      filter.gender = access;
    }
  }
  return appendOriginAccessToFilter(filter, user);
};

const buildPersonFilter = ({ queryParams, user }) => {
  const { gender, year, origin, college, university, search } = queryParams;
  const filter = { isActive: true };

  // Apply gender filter based on user permissions
  const requestedGender = normalizeGender(gender);
  if (requestedGender === 'boy' || requestedGender === 'girl') {
    filter.gender = requestedGender;
  } else if (user.role !== 'super_admin') {
    const access = userAccessibleGender(user);
    if (access !== 'both') {
      filter.gender = access;
    }
  }

  if (year) filter.year = Number.parseInt(year, 10);
  if (origin) filter.origin = new RegExp(escapeRegExp(String(origin).trim()), 'i');
  if (college) filter.college = new RegExp(escapeRegExp(String(college).trim()), 'i');
  if (university) filter.university = new RegExp(escapeRegExp(String(university).trim()), 'i');

  // Search filter
  if (search) {
    const safeSearch = new RegExp(escapeRegExp(String(search).trim()), 'i');
    filter.$or = [
      { name: safeSearch },
      { college: safeSearch },
      { university: safeSearch },
      { origin: safeSearch },
      { residence: safeSearch }
    ];
  }

  return appendOriginAccessToFilter(filter, user);
};

const toSafeCustomFields = (customFields) => {
  if (!customFields || typeof customFields !== 'object' || Array.isArray(customFields)) {
    return undefined;
  }
  return new Map(
    Object.entries(customFields).map(([key, value]) => [String(key), value == null ? '' : String(value)])
  );
};

const pickPersonPayload = (bodyPayload) => {
  const data = {};
  for (const [key, value] of Object.entries(bodyPayload)) {
    if (PERSON_MUTABLE_FIELDS.has(key)) {
      data[key] = value;
    }
  }

  if (Object.prototype.hasOwnProperty.call(data, 'customFields')) {
    const mapValue = toSafeCustomFields(data.customFields);
    if (mapValue) {
      data.customFields = mapValue;
    } else {
      delete data.customFields;
    }
  }

  return data;
};

// @route   GET /api/persons
// @desc    Get all persons with filters
// @access  Private
router.get('/', [
  authenticateToken,
  checkGenderAccess,
  ...validate([
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 200 }),
    query('gender').optional().isIn(['boy', 'girl']),
    query('year').optional().isInt({ min: 1, max: 5 })
  ])
], asyncHandler(async (req, res) => {
  const { page, limit } = parsePagination(req.query.page, req.query.limit);
  const filter = buildPersonFilter({ queryParams: req.query, user: req.user });
  const skip = (page - 1) * limit;
  const cacheKey = `${PERSONS_CACHE_PREFIX}${req.user._id.toString()}:${JSON.stringify(filter)}:${page}:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const [persons, total] = await Promise.all([
    Person.find(filter)
      .populate('createdBy', 'username')
      .populate('notes.createdBy', 'username')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean(),
    Person.countDocuments(filter)
  ]);

  const payload = {
    success: true,
    persons,
    pagination: {
      current: page,
      pages: Math.ceil(total / limit),
      total
    }
  };

  cache.set(cacheKey, payload, 20 * 1000);
  return res.json(payload);
}));

// @route   GET /api/persons/stats/overview
// @desc    Get statistics overview
// @access  Private
router.get('/stats/overview', [
  authenticateToken,
  checkGenderAccess
], asyncHandler(async (req, res) => {
  const filter = buildPersonFilter({
    queryParams: { gender: req.query.gender },
    user: req.user
  });

  const cacheKey = `${STATS_CACHE_PREFIX}${req.user._id.toString()}:${JSON.stringify(filter)}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const genderForFilter = filter.gender;
  const [totalCount, boysCount, girlsCount, yearStats, originStats] = await Promise.all([
    Person.countDocuments(filter),
    genderForFilter && genderForFilter !== 'boy'
      ? 0
      : Person.countDocuments({ ...filter, gender: 'boy' }),
    genderForFilter && genderForFilter !== 'girl'
      ? 0
      : Person.countDocuments({ ...filter, gender: 'girl' }),
    Person.aggregate([
      { $match: filter },
      { $group: { _id: '$year', count: { $sum: 1 } } },
      { $sort: { _id: 1 } }
    ]),
    Person.aggregate([
      { $match: filter },
      { $group: { _id: '$origin', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ])
  ]);

  const payload = {
    success: true,
    stats: {
      total: totalCount,
      boys: boysCount,
      girls: girlsCount,
      byYear: yearStats,
      topOrigins: originStats
    }
  };

  cache.set(cacheKey, payload, 30 * 1000);
  return res.json(payload);
}));

// @route   GET /api/persons/form-options
// @desc    Get saved values for person form fields
// @access  Private
router.get('/form-options', [
  authenticateToken,
  checkGenderAccess
], asyncHandler(async (req, res) => {
  const filter = buildFormOptionsMatch(req.user);
  const cacheKey = `${FORM_OPTIONS_CACHE_PREFIX}${req.user._id.toString()}:${JSON.stringify(filter)}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const [colleges, universities, residences, origins, customFieldData] = await Promise.all([
    Person.distinct('college', filter),
    Person.distinct('university', filter),
    Person.distinct('residence', filter),
    Person.distinct('origin', filter),
    Person.aggregate([
      { $match: filter },
      {
        $project: {
          customPairs: { $objectToArray: { $ifNull: ['$customFields', {}] } }
        }
      },
      { $unwind: '$customPairs' },
      {
        $project: {
          key: { $trim: { input: { $toString: '$customPairs.k' } } },
          value: { $trim: { input: { $toString: '$customPairs.v' } } }
        }
      },
      {
        $match: {
          key: { $ne: '' },
          value: { $ne: '' }
        }
      },
      {
        $group: {
          _id: '$key',
          values: { $addToSet: '$value' }
        }
      },
      {
        $project: {
          _id: 0,
          key: '$_id',
          values: 1
        }
      }
    ])
  ]);

  const customFieldKeys = normalizeOptionValues(customFieldData.map((entry) => entry.key));
  const customFieldValuesByKey = {};
  for (const entry of customFieldData) {
    if (!entry || !entry.key) continue;
    customFieldValuesByKey[entry.key] = normalizeOptionValues(entry.values);
  }

  const payload = {
    success: true,
    formOptions: {
      college: normalizeOptionValues(colleges),
      university: normalizeOptionValues(universities),
      residence: normalizeOptionValues(residences),
      origin: normalizeOptionValues(origins),
      customFieldKeys,
      customFieldValuesByKey
    }
  };

  cache.set(cacheKey, payload, 60 * 1000);
  return res.json(payload);
}));

// @route   GET /api/persons/:id
// @desc    Get single person
// @access  Private
router.get('/:id', [
  authenticateToken,
  checkGenderAccess
], asyncHandler(async (req, res) => {
  const person = await Person.findById(req.params.id)
    .populate('createdBy', 'username')
    .populate('notes.createdBy', 'username');

  if (!person || !person.isActive) {
    return res.status(404).json({
      success: false,
      message: 'الشخص غير موجود'
    });
  }

  // Check access boundaries (gender + origin)
  if (!hasGenderAccess(req.user, person.gender) || !hasOriginAccess(req.user, person.origin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  return res.json({
    success: true,
    person
  });
}));

// @route   POST /api/persons
// @desc    Create new person
// @access  Private (with create permission)
router.post('/', [
  authenticateToken,
  checkPermission(['create_data']),
  ...validate([
    body('name').trim().notEmpty().withMessage('الاسم مطلوب'),
    body('gender').isIn(['boy', 'girl']).withMessage('النوع يجب أن يكون ولد أو بنت'),
    body('year').isInt({ min: 1, max: 5 }).withMessage('السنة يجب أن تكون بين 1 و 5'),
    body('phone').trim().notEmpty().withMessage('رقم الهاتف مطلوب'),
    body('origin').trim().notEmpty().withMessage('البلد الأصلية مطلوبة')
  ])
], asyncHandler(async (req, res) => {
  const personData = {
    ...pickPersonPayload(req.body),
    createdBy: req.user._id
  };

  if (!hasOriginAccess(req.user, personData.origin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  const person = new Person(personData);
  await person.save();
  await person.populate('createdBy', 'username');
  clearPersonCaches();

  return res.status(201).json({
    success: true,
    message: 'تم إنشاء الشخص بنجاح',
    person
  });
}));

// @route   PUT /api/persons/:id
// @desc    Update person
// @access  Private (with edit permission)
router.put('/:id', [
  authenticateToken,
  checkPermission(['edit_data']),
  ...validate([
    body('name').trim().notEmpty().withMessage('الاسم مطلوب'),
    body('gender').isIn(['boy', 'girl']).withMessage('النوع يجب أن يكون ولد أو بنت'),
    body('year').isInt({ min: 1, max: 5 }).withMessage('السنة يجب أن تكون بين 1 و 5'),
    body('phone').trim().notEmpty().withMessage('رقم الهاتف مطلوب'),
    body('origin').trim().notEmpty().withMessage('البلد الأصلية مطلوبة')
  ])
], asyncHandler(async (req, res) => {
  const person = await Person.findById(req.params.id);

  if (!person || !person.isActive) {
    return res.status(404).json({
      success: false,
      message: 'الشخص غير موجود'
    });
  }

  // Check access boundaries (gender + origin)
  if (!hasGenderAccess(req.user, person.gender) || !hasOriginAccess(req.user, person.origin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  const updateData = pickPersonPayload(req.body);
  const targetOrigin = Object.prototype.hasOwnProperty.call(updateData, 'origin')
    ? updateData.origin
    : person.origin;

  if (!hasOriginAccess(req.user, targetOrigin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  Object.assign(person, updateData);
  await person.save();
  await person.populate('createdBy', 'username');
  clearPersonCaches();

  return res.json({
    success: true,
    message: 'تم تحديث الشخص بنجاح',
    person
  });
}));

// @route   DELETE /api/persons/:id
// @desc    Delete person (soft delete)
// @access  Private (with delete permission)
router.delete('/:id', [
  authenticateToken,
  checkPermission(['delete_data'])
], asyncHandler(async (req, res) => {
  const person = await Person.findById(req.params.id);

  if (!person || !person.isActive) {
    return res.status(404).json({
      success: false,
      message: 'الشخص غير موجود'
    });
  }

  // Check access boundaries (gender + origin)
  if (!hasGenderAccess(req.user, person.gender) || !hasOriginAccess(req.user, person.origin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  person.isActive = false;
  await person.save();
  clearPersonCaches();

  return res.json({
    success: true,
    message: 'تم حذف الشخص بنجاح'
  });
}));

// @route   POST /api/persons/:id/notes
// @desc    Add note to person
// @access  Private (with manage_notes permission)
router.post('/:id/notes', [
  authenticateToken,
  checkPermission(['manage_notes']),
  ...validate([
    body('content')
      .trim()
      .notEmpty()
      .withMessage('محتوى الملاحظة مطلوب')
      .isLength({ max: 500 })
      .withMessage('محتوى الملاحظة طويل جدًا')
  ])
], asyncHandler(async (req, res) => {
  const { content } = req.body;
  const personId = req.params.id;

  const person = await Person.findById(personId);
  if (!person || !person.isActive) {
    return res.status(404).json({
      success: false,
      message: 'الشخص غير موجود'
    });
  }

  // Check access boundaries (gender + origin)
  if (!hasGenderAccess(req.user, person.gender) || !hasOriginAccess(req.user, person.origin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  const newNote = {
    content,
    createdBy: req.user._id,
    createdAt: new Date()
  };

  person.notes.push(newNote);
  await person.save();

  // Populate the note creator
  await person.populate('notes.createdBy', 'username');
  clearPersonCaches();

  return res.status(201).json({
    success: true,
    message: 'تم إضافة الملاحظة بنجاح',
    note: person.notes[person.notes.length - 1]
  });
}));

// @route   DELETE /api/persons/:id/notes/:noteId
// @desc    Delete note from person
// @access  Private (with manage_notes permission)
router.delete('/:id/notes/:noteId', [
  authenticateToken,
  checkPermission(['manage_notes'])
], asyncHandler(async (req, res) => {
  const personId = req.params.id;
  const noteId = req.params.noteId;

  const person = await Person.findById(personId);
  if (!person || !person.isActive) {
    return res.status(404).json({
      success: false,
      message: 'الشخص غير موجود'
    });
  }

  // Check access boundaries (gender + origin)
  if (!hasGenderAccess(req.user, person.gender) || !hasOriginAccess(req.user, person.origin)) {
    return res.status(403).json({
      success: false,
      message: 'تم رفض الوصول'
    });
  }

  const noteIndex = person.notes.findIndex((note) => note._id.toString() === noteId);
  if (noteIndex === -1) {
    return res.status(404).json({
      success: false,
      message: 'الملاحظة غير موجودة'
    });
  }

  person.notes.splice(noteIndex, 1);
  await person.save();
  clearPersonCaches();

  return res.json({
    success: true,
    message: 'تم حذف الملاحظة بنجاح'
  });
}));

module.exports = router;