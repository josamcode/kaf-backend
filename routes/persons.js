const express = require('express');
const mongoose = require('mongoose');
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
const NOTES_LIST_CACHE_PREFIX = 'persons:notes:list:';
const NOTES_FILTER_OPTIONS_CACHE_PREFIX = 'persons:notes:filter-options:';
const PERSON_WRITE_CACHE_PREFIXES = [
  STATS_CACHE_PREFIX,
  PERSONS_CACHE_PREFIX,
  FORM_OPTIONS_CACHE_PREFIX,
  NOTES_LIST_CACHE_PREFIX,
  NOTES_FILTER_OPTIONS_CACHE_PREFIX
];
const ALLOWED_YEARS = new Set([1, 2, 3, 4, 5, 'graduated']);
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

const normalizeYearValue = (value) => {
  if (value === 'graduated') return 'graduated';
  const parsed = Number.parseInt(value, 10);
  return [1, 2, 3, 4, 5].includes(parsed) ? parsed : undefined;
};

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

const serializeCacheSegment = (value) => JSON.stringify(value, (_key, currentValue) => {
  if (currentValue instanceof RegExp) {
    return {
      type: 'regex',
      source: currentValue.source,
      flags: currentValue.flags
    };
  }

  return currentValue;
});

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

const buildTopTextFieldPipeline = (filter, fieldName, limit = 10) => ([
  { $match: filter },
  {
    $project: {
      value: {
        $trim: {
          input: {
            $toString: {
              $ifNull: [`$${fieldName}`, '']
            }
          }
        }
      }
    }
  },
  { $match: { value: { $ne: '' } } },
  { $group: { _id: '$value', count: { $sum: 1 } } },
  { $sort: { count: -1 } },
  { $limit: limit }
]);

const buildCustomPairsBasePipeline = (filter) => ([
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
  }
]);

const buildPersonFilter = ({ queryParams, user, includeSearch = true }) => {
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

  if (year) {
    const normalizedYear = normalizeYearValue(year);
    if (normalizedYear !== undefined) {
      filter.year = normalizedYear;
    }
  }
  if (origin) filter.origin = new RegExp(escapeRegExp(String(origin).trim()), 'i');
  if (college) filter.college = new RegExp(escapeRegExp(String(college).trim()), 'i');
  if (university) filter.university = new RegExp(escapeRegExp(String(university).trim()), 'i');

  // Search filter
  if (includeSearch && search) {
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

const buildNotesSearchMatch = (search) => {
  if (!search) return null;

  const safeSearch = new RegExp(escapeRegExp(String(search).trim()), 'i');
  return {
    $or: [
      { 'notes.content': safeSearch },
      { name: safeSearch },
      { origin: safeSearch },
      { college: safeSearch },
      { university: safeSearch },
      { residence: safeSearch },
      { 'noteAuthor.username': safeSearch }
    ]
  };
};

const buildNotesAggregationStages = ({ personFilter, search, authorId }) => {
  const stages = [
    { $match: personFilter },
    {
      $project: {
        name: 1,
        gender: 1,
        year: 1,
        origin: 1,
        phone: 1,
        college: 1,
        university: 1,
        residence: 1,
        notes: 1
      }
    },
    { $unwind: '$notes' }
  ];

  if (authorId) {
    stages.push({
      $match: {
        'notes.createdBy': new mongoose.Types.ObjectId(authorId)
      }
    });
  }

  stages.push(
    {
      $lookup: {
        from: 'servants',
        localField: 'notes.createdBy',
        foreignField: '_id',
        as: 'noteAuthor'
      }
    },
    {
      $unwind: {
        path: '$noteAuthor',
        preserveNullAndEmptyArrays: true
      }
    }
  );

  const notesSearchMatch = buildNotesSearchMatch(search);
  if (notesSearchMatch) {
    stages.push({ $match: notesSearchMatch });
  }

  return stages;
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

  if (Object.prototype.hasOwnProperty.call(data, 'year')) {
    const normalizedYear = normalizeYearValue(data.year);
    if (normalizedYear === undefined) {
      delete data.year;
    } else {
      data.year = normalizedYear;
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
    query('noLimit').optional().isBoolean(),
    query('gender').optional().isIn(['boy', 'girl']),
    query('year')
      .optional()
      .custom((value) => ALLOWED_YEARS.has(normalizeYearValue(value)))
  ])
], asyncHandler(async (req, res) => {
  const noLimit = String(req.query.noLimit || '').toLowerCase() === 'true';
  const { page, limit } = parsePagination(req.query.page, req.query.limit);
  const filter = buildPersonFilter({ queryParams: req.query, user: req.user });
  const currentPage = noLimit ? 1 : page;
  const skip = (currentPage - 1) * limit;
  const cacheKey = `${PERSONS_CACHE_PREFIX}${req.user._id.toString()}:${serializeCacheSegment(filter)}:${currentPage}:${limit}:${noLimit ? 'all' : 'paged'}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const personsQuery = Person.find(filter)
    .populate('createdBy', 'username')
    .populate('notes.createdBy', 'username')
    .sort({ createdAt: -1 });

  if (!noLimit) {
    personsQuery.skip(skip).limit(limit);
  }

  const [persons, total] = await Promise.all([
    personsQuery.lean(),
    Person.countDocuments(filter)
  ]);

  const payload = {
    success: true,
    persons,
    pagination: {
      current: currentPage,
      pages: noLimit ? 1 : Math.ceil(total / limit),
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

  const cacheKey = `${STATS_CACHE_PREFIX}${req.user._id.toString()}:${serializeCacheSegment(filter)}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const genderForFilter = filter.gender;
  const customPairsBase = buildCustomPairsBasePipeline(filter);
  const [totalCount, boysCount, girlsCount, yearStats, originStats, collegeStats, universityStats, servantStats, noteAuthorStats, notesSummaryAgg, customFieldsSummaryAgg, customFieldKeysCountAgg, topCustomFields, customFieldDetails, uniqueServantsContributedAgg] = await Promise.all([
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
    ]),
    Person.aggregate(buildTopTextFieldPipeline(filter, 'college', 8)),
    Person.aggregate(buildTopTextFieldPipeline(filter, 'university', 8)),
    Person.aggregate([
      { $match: filter },
      { $group: { _id: '$createdBy', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 8 },
      {
        $lookup: {
          from: 'servants',
          localField: '_id',
          foreignField: '_id',
          as: 'servant'
        }
      },
      {
        $unwind: {
          path: '$servant',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          _id: {
            $ifNull: [
              '$servant.username',
              {
                $concat: ['#', { $toString: '$_id' }]
              }
            ]
          },
          count: 1
        }
      }
    ]),
    Person.aggregate([
      { $match: filter },
      { $unwind: '$notes' },
      { $group: { _id: '$notes.createdBy', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 8 },
      {
        $lookup: {
          from: 'servants',
          localField: '_id',
          foreignField: '_id',
          as: 'servant'
        }
      },
      {
        $unwind: {
          path: '$servant',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          _id: {
            $ifNull: [
              '$servant.username',
              {
                $concat: ['#', { $toString: '$_id' }]
              }
            ]
          },
          count: 1
        }
      }
    ]),
    Person.aggregate([
      { $match: filter },
      {
        $project: {
          notesCount: { $size: { $ifNull: ['$notes', []] } }
        }
      },
      {
        $group: {
          _id: null,
          notesTotal: { $sum: '$notesCount' },
          personsWithNotes: {
            $sum: {
              $cond: [{ $gt: ['$notesCount', 0] }, 1, 0]
            }
          }
        }
      }
    ]),
    Person.aggregate([
      { $match: filter },
      {
        $project: {
          customPairs: { $objectToArray: { $ifNull: ['$customFields', {}] } }
        }
      },
      {
        $project: {
          pairCount: { $size: '$customPairs' }
        }
      },
      {
        $group: {
          _id: null,
          personsWithCustomFields: {
            $sum: {
              $cond: [{ $gt: ['$pairCount', 0] }, 1, 0]
            }
          },
          customFieldsTotalEntries: { $sum: '$pairCount' }
        }
      }
    ]),
    Person.aggregate([
      ...customPairsBase,
      { $group: { _id: '$key' } },
      { $count: 'count' }
    ]),
    Person.aggregate([
      ...customPairsBase,
      {
        $group: {
          _id: '$key',
          count: { $sum: 1 },
          uniqueValues: { $addToSet: '$value' }
        }
      },
      {
        $project: {
          _id: 1,
          count: 1,
          uniqueValuesCount: { $size: '$uniqueValues' }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]),
    Person.aggregate([
      ...customPairsBase,
      {
        $group: {
          _id: { key: '$key', value: '$value' },
          count: { $sum: 1 }
        }
      },
      { $sort: { '_id.key': 1, count: -1 } },
      {
        $group: {
          _id: '$_id.key',
          totalCount: { $sum: '$count' },
          uniqueValuesCount: { $sum: 1 },
          topValues: {
            $push: {
              value: '$_id.value',
              count: '$count'
            }
          }
        }
      },
      {
        $project: {
          _id: 1,
          totalCount: 1,
          uniqueValuesCount: 1,
          topValues: { $slice: ['$topValues', 5] }
        }
      },
      { $sort: { totalCount: -1 } },
      { $limit: 6 }
    ]),
    Person.aggregate([
      { $match: filter },
      { $group: { _id: '$createdBy' } },
      { $count: 'count' }
    ])
  ]);

  const notesSummary = notesSummaryAgg[0] || {};
  const customFieldsSummary = customFieldsSummaryAgg[0] || {};
  const customFieldKeysCount = customFieldKeysCountAgg[0]?.count || 0;
  const uniqueServantsContributed = uniqueServantsContributedAgg[0]?.count || 0;

  const payload = {
    success: true,
    stats: {
      total: totalCount,
      boys: boysCount,
      girls: girlsCount,
      byYear: yearStats,
      topOrigins: originStats,
      topColleges: collegeStats,
      topUniversities: universityStats,
      topServants: servantStats,
      topNoteAuthors: noteAuthorStats,
      notesTotal: notesSummary.notesTotal || 0,
      personsWithNotes: notesSummary.personsWithNotes || 0,
      personsWithCustomFields: customFieldsSummary.personsWithCustomFields || 0,
      customFieldsTotalEntries: customFieldsSummary.customFieldsTotalEntries || 0,
      customFieldKeysCount,
      uniqueServantsContributed,
      topCustomFields,
      customFieldDetails
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
  const cacheKey = `${FORM_OPTIONS_CACHE_PREFIX}${req.user._id.toString()}:${serializeCacheSegment(filter)}`;
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

// @route   GET /api/persons/notes/filter-options
// @desc    Get filter options for the notes page
// @access  Private (with manage_notes permission)
router.get('/notes/filter-options', [
  authenticateToken,
  checkPermission(['manage_notes']),
  checkGenderAccess,
  ...validate([
    query('gender').optional().isIn(['boy', 'girl']),
    query('year')
      .optional()
      .custom((value) => ALLOWED_YEARS.has(normalizeYearValue(value)))
  ])
], asyncHandler(async (req, res) => {
  const personFilter = buildPersonFilter({
    queryParams: req.query,
    user: req.user,
    includeSearch: false
  });

  const cacheKey = `${NOTES_FILTER_OPTIONS_CACHE_PREFIX}${req.user._id.toString()}:${serializeCacheSegment(personFilter)}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const [origins, authorsAgg] = await Promise.all([
    Person.distinct('origin', personFilter),
    Person.aggregate([
      { $match: personFilter },
      { $unwind: '$notes' },
      { $group: { _id: '$notes.createdBy' } },
      {
        $lookup: {
          from: 'servants',
          localField: '_id',
          foreignField: '_id',
          as: 'servant'
        }
      },
      {
        $unwind: {
          path: '$servant',
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          _id: 0,
          value: { $toString: '$_id' },
          label: {
            $ifNull: [
              '$servant.username',
              {
                $concat: ['#', { $toString: '$_id' }]
              }
            ]
          }
        }
      }
    ])
  ]);

  const authors = authorsAgg.sort((a, b) =>
    String(a.label || '').localeCompare(String(b.label || ''), 'ar', {
      sensitivity: 'base'
    })
  );

  const payload = {
    success: true,
    filterOptions: {
      origins: normalizeOptionValues(origins),
      authors
    }
  };

  cache.set(cacheKey, payload, 60 * 1000);
  return res.json(payload);
}));

// @route   GET /api/persons/notes
// @desc    Get all accessible notes with filters
// @access  Private (with manage_notes permission)
router.get('/notes', [
  authenticateToken,
  checkPermission(['manage_notes']),
  checkGenderAccess,
  ...validate([
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('gender').optional().isIn(['boy', 'girl']),
    query('authorId').optional().isMongoId(),
    query('year')
      .optional()
      .custom((value) => ALLOWED_YEARS.has(normalizeYearValue(value)))
  ])
], asyncHandler(async (req, res) => {
  const { page, limit } = parsePagination(req.query.page, req.query.limit);
  const skip = (page - 1) * limit;
  const personFilter = buildPersonFilter({
    queryParams: req.query,
    user: req.user,
    includeSearch: false
  });
  const search = String(req.query.search || '').trim();
  const authorId = req.query.authorId ? String(req.query.authorId) : undefined;
  const cacheKey = `${NOTES_LIST_CACHE_PREFIX}${req.user._id.toString()}:${serializeCacheSegment(personFilter)}:${search}:${authorId || 'all'}:${page}:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) {
    return res.json(cached);
  }

  const notesBaseStages = buildNotesAggregationStages({
    personFilter,
    search,
    authorId
  });

  const aggregateResult = await Person.aggregate([
    ...notesBaseStages,
    { $sort: { 'notes.createdAt': -1, _id: -1 } },
    {
      $facet: {
        notes: [
          { $skip: skip },
          { $limit: limit },
          {
            $project: {
              _id: '$notes._id',
              content: '$notes.content',
              createdAt: '$notes.createdAt',
              createdBy: {
                _id: '$notes.createdBy',
                username: { $ifNull: ['$noteAuthor.username', 'Unknown'] }
              },
              person: {
                _id: '$_id',
                name: '$name',
                gender: '$gender',
                year: '$year',
                origin: '$origin',
                phone: '$phone',
                college: '$college',
                university: '$university',
                residence: '$residence'
              }
            }
          }
        ],
        totalCount: [{ $count: 'count' }]
      }
    }
  ]);

  const result = aggregateResult[0] || { notes: [], totalCount: [] };
  const total = result.totalCount[0]?.count || 0;
  const payload = {
    success: true,
    notes: result.notes,
    pagination: {
      current: page,
      pages: Math.max(Math.ceil(total / limit), 1),
      total
    }
  };

  cache.set(cacheKey, payload, 20 * 1000);
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
    body('year')
      .custom((value) => ALLOWED_YEARS.has(normalizeYearValue(value)))
      .withMessage('السنة يجب أن تكون بين 1 و 5 أو خريج'),
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
    body('year')
      .custom((value) => ALLOWED_YEARS.has(normalizeYearValue(value)))
      .withMessage('السنة يجب أن تكون بين 1 و 5 أو خريج'),
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
