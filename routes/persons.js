const express = require('express');
const { body, validationResult } = require('express-validator');
const Person = require('../models/Person');
const { authenticateToken, checkPermission, checkGenderAccess } = require('../middleware/auth');

const router = express.Router();

// @route   GET /api/persons
// @desc    Get all persons with filters
// @access  Private
router.get('/', [
  authenticateToken,
  checkGenderAccess
], async (req, res) => {
  try {
    const {
      gender,
      year,
      origin,
      college,
      university,
      search,
      page = 1,
      limit = 50
    } = req.query;

    // Build filter object
    const filter = { isActive: true };

    // Apply gender filter based on user permissions
    if (gender) {
      filter.gender = gender;
    } else if (req.user.role !== 'super_admin') {
      // If user doesn't have access to both genders, filter by their access
      if (req.user.genderAccess !== 'both') {
        filter.gender = req.user.genderAccess === 'boys' ? 'boy' : 'girl';
      }
    }

    if (year) filter.year = parseInt(year);
    if (origin) filter.origin = new RegExp(origin, 'i');
    if (college) filter.college = new RegExp(college, 'i');
    if (university) filter.university = new RegExp(university, 'i');

    // Search filter
    if (search) {
      filter.$or = [
        { name: new RegExp(search, 'i') },
        { college: new RegExp(search, 'i') },
        { university: new RegExp(search, 'i') },
        { origin: new RegExp(search, 'i') },
        { residence: new RegExp(search, 'i') }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const persons = await Person.find(filter)
      .populate('createdBy', 'username')
      .populate('notes.createdBy', 'username')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Person.countDocuments(filter);

    res.json({
      success: true,
      persons,
      pagination: {
        current: parseInt(page),
        pages: Math.ceil(total / parseInt(limit)),
        total
      }
    });

  } catch (error) {
    console.error('Get persons error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   GET /api/persons/:id
// @desc    Get single person
// @access  Private
router.get('/:id', [
  authenticateToken,
  checkGenderAccess
], async (req, res) => {
  try {
    const person = await Person.findById(req.params.id)
      .populate('createdBy', 'username')
      .populate('notes.createdBy', 'username');

    if (!person || !person.isActive) {
      return res.status(404).json({
        success: false,
        message: 'الشخص غير موجود'
      });
    }

    // Check gender access
    if (req.user.role !== 'super_admin' &&
      req.user.genderAccess !== 'both' &&
      req.user.genderAccess !== person.gender + 's') {
      return res.status(403).json({
        success: false,
        message: 'تم رفض الوصول'
      });
    }

    res.json({
      success: true,
      person
    });

  } catch (error) {
    console.error('Get person error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   POST /api/persons
// @desc    Create new person
// @access  Private (with create permission)
router.post('/', [
  authenticateToken,
  checkPermission(['create_data']),
  body('name').notEmpty().withMessage('الاسم مطلوب'),
  body('gender').isIn(['boy', 'girl']).withMessage('النوع يجب أن يكون ولد أو بنت'),
  body('year').isInt({ min: 1, max: 5 }).withMessage('السنة يجب أن تكون بين 1 و 5'),
  body('phone').notEmpty().withMessage('رقم الهاتف مطلوب'),
  body('origin').notEmpty().withMessage('البلد الأصلية مطلوبة')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array()
      });
    }

    const personData = {
      ...req.body,
      createdBy: req.user._id
    };

    // Convert customFields object to Map if it exists
    if (personData.customFields && typeof personData.customFields === 'object') {
      personData.customFields = new Map(Object.entries(personData.customFields));
    } else if (personData.customFields === undefined) {
      // Don't set customFields if it's undefined
      delete personData.customFields;
    }

    const person = new Person(personData);
    await person.save();

    await person.populate('createdBy', 'username');

    res.status(201).json({
      success: true,
      message: 'تم إنشاء الشخص بنجاح',
      person
    });

  } catch (error) {
    console.error('Create person error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   PUT /api/persons/:id
// @desc    Update person
// @access  Private (with edit permission)
router.put('/:id', [
  authenticateToken,
  checkPermission(['edit_data']),
  body('name').notEmpty().withMessage('الاسم مطلوب'),
  body('gender').isIn(['boy', 'girl']).withMessage('النوع يجب أن يكون ولد أو بنت'),
  body('year').isInt({ min: 1, max: 5 }).withMessage('السنة يجب أن تكون بين 1 و 5'),
  body('phone').notEmpty().withMessage('رقم الهاتف مطلوب'),
  body('origin').notEmpty().withMessage('البلد الأصلية مطلوبة')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array()
      });
    }

    const person = await Person.findById(req.params.id);

    if (!person || !person.isActive) {
      return res.status(404).json({
        success: false,
        message: 'الشخص غير موجود'
      });
    }

    // Check gender access
    if (req.user.role !== 'super_admin' &&
      req.user.genderAccess !== 'both' &&
      req.user.genderAccess !== person.gender + 's') {
      return res.status(403).json({
        success: false,
        message: 'تم رفض الوصول'
      });
    }

    // Convert customFields object to Map if it exists
    const updateData = { ...req.body };
    if (updateData.customFields && typeof updateData.customFields === 'object') {
      updateData.customFields = new Map(Object.entries(updateData.customFields));
    } else if (updateData.customFields === undefined) {
      // Don't update customFields if it's undefined
      delete updateData.customFields;
    }

    Object.assign(person, updateData);
    await person.save();

    await person.populate('createdBy', 'username');

    res.json({
      success: true,
      message: 'تم تحديث الشخص بنجاح',
      person
    });

  } catch (error) {
    console.error('Update person error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   DELETE /api/persons/:id
// @desc    Delete person (soft delete)
// @access  Private (with delete permission)
router.delete('/:id', [
  authenticateToken,
  checkPermission(['delete_data'])
], async (req, res) => {
  try {
    const person = await Person.findById(req.params.id);

    if (!person || !person.isActive) {
      return res.status(404).json({
        success: false,
        message: 'الشخص غير موجود'
      });
    }

    // Check gender access
    if (req.user.role !== 'super_admin' &&
      req.user.genderAccess !== 'both' &&
      req.user.genderAccess !== person.gender + 's') {
      return res.status(403).json({
        success: false,
        message: 'تم رفض الوصول'
      });
    }

    person.isActive = false;
    await person.save();

    res.json({
      success: true,
      message: 'تم حذف الشخص بنجاح'
    });

  } catch (error) {
    console.error('Delete person error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   GET /api/persons/stats/overview
// @desc    Get statistics overview
// @access  Private
router.get('/stats/overview', [
  authenticateToken,
  checkGenderAccess
], async (req, res) => {
  try {
    const { gender } = req.query;

    // Build filter object
    const filter = { isActive: true };

    // Apply gender filter based on user permissions
    if (gender) {
      filter.gender = gender;
    } else if (req.user.role !== 'super_admin') {
      if (req.user.genderAccess !== 'both') {
        filter.gender = req.user.genderAccess === 'boys' ? 'boy' : 'girl';
      }
    }

    const [
      totalCount,
      boysCount,
      girlsCount,
      yearStats,
      originStats
    ] = await Promise.all([
      Person.countDocuments(filter),
      Person.countDocuments({ ...filter, gender: 'boy' }),
      Person.countDocuments({ ...filter, gender: 'girl' }),
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

    res.json({
      success: true,
      stats: {
        total: totalCount,
        boys: boysCount,
        girls: girlsCount,
        byYear: yearStats,
        topOrigins: originStats
      }
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   POST /api/persons/:id/notes
// @desc    Add note to person
// @access  Private (with manage_notes permission)
router.post('/:id/notes', [
  authenticateToken,
  checkPermission(['manage_notes']),
  body('content').notEmpty().withMessage('محتوى الملاحظة مطلوب').isLength({ max: 500 }).withMessage('محتوى الملاحظة طويل جداً')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation errors',
        errors: errors.array()
      });
    }

    const { content } = req.body;
    const personId = req.params.id;

    const person = await Person.findById(personId);
    if (!person || !person.isActive) {
      return res.status(404).json({
        success: false,
        message: 'الشخص غير موجود'
      });
    }

    // Check gender access
    if (req.user.role !== 'super_admin' &&
      req.user.genderAccess !== 'both' &&
      req.user.genderAccess !== person.gender + 's') {
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

    res.status(201).json({
      success: true,
      message: 'تم إضافة الملاحظة بنجاح',
      note: person.notes[person.notes.length - 1]
    });

  } catch (error) {
    console.error('Add note error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// @route   DELETE /api/persons/:id/notes/:noteId
// @desc    Delete note from person
// @access  Private (with manage_notes permission)
router.delete('/:id/notes/:noteId', [
  authenticateToken,
  checkPermission(['manage_notes'])
], async (req, res) => {
  try {
    const personId = req.params.id;
    const noteId = req.params.noteId;

    const person = await Person.findById(personId);
    if (!person || !person.isActive) {
      return res.status(404).json({
        success: false,
        message: 'الشخص غير موجود'
      });
    }

    // Check gender access
    if (req.user.role !== 'super_admin' &&
      req.user.genderAccess !== 'both' &&
      req.user.genderAccess !== person.gender + 's') {
      return res.status(403).json({
        success: false,
        message: 'تم رفض الوصول'
      });
    }

    const noteIndex = person.notes.findIndex(note => note._id.toString() === noteId);
    if (noteIndex === -1) {
      return res.status(404).json({
        success: false,
        message: 'الملاحظة غير موجودة'
      });
    }

    person.notes.splice(noteIndex, 1);
    await person.save();

    res.json({
      success: true,
      message: 'تم حذف الملاحظة بنجاح'
    });

  } catch (error) {
    console.error('Delete note error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

module.exports = router;
