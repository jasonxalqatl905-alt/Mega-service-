// =============================================
// MEGA SERVICES - COMPLETE BACKEND (Single File)
// =============================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { body, validationResult } = require('express-validator');

const app = express();

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ===== DATABASE CONNECTION =====
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/mega-services';
mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ===== DATABASE MODELS =====

// User Model
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'الاسم مطلوب'],
        trim: true,
        maxlength: [50, 'الاسم لا يمكن أن يزيد عن 50 حرف']
    },
    email: {
        type: String,
        required: [true, 'البريد الإلكتروني مطلوب'],
        unique: true,
        lowercase: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'البريد الإلكتروني غير صحيح']
    },
    password: {
        type: String,
        required: [true, 'كلمة المرور مطلوبة'],
        minlength: [6, 'كلمة المرور يجب أن تكون 6 أحرف على الأقل'],
        select: false
    },
    phone: {
        type: String,
        required: [true, 'رقم الهاتف مطلوب'],
        match: [/^01[0-2,5]{1}[0-9]{8}$/, 'رقم الهاتف غير صحيح']
    },
    role: {
        type: String,
        enum: ['user', 'admin', 'manager'],
        default: 'user'
    },
    profileImage: String,
    preferences: {
        language: {
            type: String,
            enum: ['ar', 'en'],
            default: 'ar'
        },
        notifications: {
            email: { type: Boolean, default: true },
            sms: { type: Boolean, default: true }
        }
    },
    loyaltyPoints: {
        type: Number,
        default: 0
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

// Remove password from JSON output
userSchema.methods.toJSON = function() {
    const user = this.toObject();
    delete user.password;
    return user;
};

const User = mongoose.model('User', userSchema);

// Booking Model
const bookingSchema = new mongoose.Schema({
    bookingNumber: {
        type: String,
        unique: true,
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    serviceType: {
        type: String,
        required: [true, 'نوع الخدمة مطلوب'],
        enum: ['resort', 'dining', 'tour', 'spa', 'package']
    },
    serviceDetails: {
        name: { type: String, required: true },
        description: { type: String },
        basePrice: { type: Number, required: true }
    },
    checkIn: {
        type: Date,
        required: [true, 'تاريخ الوصول مطلوب']
    },
    checkOut: {
        type: Date,
        required: [true, 'تاريخ المغادرة مطلوب']
    },
    guests: {
        adults: {
            type: Number,
            required: true,
            min: [1, 'يجب أن يكون عدد البالغين 1 على الأقل'],
            max: [10, 'لا يمكن أن يزيد عدد البالغين عن 10']
        },
        children: {
            type: Number,
            default: 0,
            min: 0,
            max: [5, 'لا يمكن أن يزيد عدد الأطفال عن 5']
        }
    },
    guestInfo: {
        name: { type: String, required: true },
        email: { type: String, required: true },
        phone: { type: String, required: true },
        specialRequests: { type: String }
    },
    pricing: {
        baseAmount: { type: Number, required: true },
        taxAmount: { type: Number, default: 0 },
        discountAmount: { type: Number, default: 0 },
        totalAmount: { type: Number, required: true },
        currency: { type: String, default: 'USD' }
    },
    status: {
        type: String,
        enum: ['pending', 'confirmed', 'cancelled', 'completed', 'no_show'],
        default: 'pending'
    },
    paymentStatus: {
        type: String,
        enum: ['pending', 'paid', 'failed', 'refunded', 'partially_refunded'],
        default: 'pending'
    },
    paymentMethod: {
        type: String,
        enum: ['credit_card', 'debit_card', 'bank_transfer', 'qr_code', 'cash'],
        default: 'credit_card'
    },
    specialRequests: {
        type: String,
        maxlength: [500, 'لا يمكن أن تزيد الطلبات الخاصة عن 500 حرف']
    },
    cancellation: {
        isCancelled: { type: Boolean, default: false },
        cancelledAt: Date,
        cancellationReason: String,
        refundAmount: Number
    }
}, {
    timestamps: true
});

// Generate booking number before saving
bookingSchema.pre('save', async function(next) {
    if (this.isNew) {
        const count = await mongoose.model('Booking').countDocuments();
        this.bookingNumber = `MG${String(count + 1).padStart(6, '0')}`;
    }
    next();
});

// Calculate total nights
bookingSchema.virtual('totalNights').get(function() {
    return Math.ceil((this.checkOut - this.checkIn) / (1000 * 60 * 60 * 24));
});

// Check if booking can be cancelled (within 48 hours of check-in)
bookingSchema.methods.canBeCancelled = function() {
    const hoursUntilCheckIn = (this.checkIn - new Date()) / (1000 * 60 * 60);
    return hoursUntilCheckIn > 48;
};

// Calculate refund amount
bookingSchema.methods.calculateRefund = function() {
    if (!this.canBeCancelled()) {
        return this.pricing.totalAmount * 0.5; // 50% refund if within 48 hours
    }
    return this.pricing.totalAmount; // Full refund
};

const Booking = mongoose.model('Booking', bookingSchema);

// Service Model
const serviceSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'اسم الخدمة مطلوب'],
        trim: true
    },
    nameEn: {
        type: String,
        required: [true, 'Service name in English is required'],
        trim: true
    },
    description: {
        type: String,
        required: [true, 'وصف الخدمة مطلوب']
    },
    descriptionEn: {
        type: String,
        required: [true, 'Service description in English is required']
    },
    category: {
        type: String,
        required: true,
        enum: ['resort', 'dining', 'tour', 'spa', 'package']
    },
    type: {
        type: String,
        required: true,
        enum: ['standard', 'premium', 'luxury', 'exclusive']
    },
    pricing: {
        basePrice: { type: Number, required: true },
        currency: { type: String, default: 'USD' },
        isPerPerson: { type: Boolean, default: true },
        childrenDiscount: { type: Number, default: 0.5 },
        taxRate: { type: Number, default: 0.14 }
    },
    capacity: {
        minGuests: { type: Number, default: 1 },
        maxGuests: { type: Number, default: 10 }
    },
    duration: {
        value: { type: Number, required: true },
        unit: { type: String, enum: ['hours', 'days'], default: 'days' }
    },
    features: [{
        name: String,
        nameEn: String,
        icon: String,
        included: { type: Boolean, default: true }
    }],
    images: [{
        url: String,
        altText: String,
        isPrimary: { type: Boolean, default: false }
    }],
    availability: {
        isAvailable: { type: Boolean, default: true },
        maxBookingsPerDay: { type: Number, default: 10 }
    },
    ratings: {
        average: { type: Number, default: 0 },
        count: { type: Number, default: 0 }
    },
    tags: [String],
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

const Service = mongoose.model('Service', serviceSchema);

// ===== MIDDLEWARE FUNCTIONS =====

// Auth Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'لا يوجد token، صلاحية الدخول مرفوضة'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mega-services-secret');
        const user = await User.findById(decoded.userId);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Token غير صحيح'
            });
        }

        if (!user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'الحساب معطل'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(401).json({
            success: false,
            message: 'Token غير صحيح'
        });
    }
};

// Admin Auth Middleware
const adminAuth = async (req, res, next) => {
    try {
        await auth(req, res, () => {});

        if (req.user.role !== 'admin' && req.user.role !== 'manager') {
            return res.status(403).json({
                success: false,
                message: 'صلاحية غير كافية. يلزم صلاحية مدير'
            });
        }

        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'صلاحية الدخول مرفوضة'
        });
    }
};

// ===== UTILITY FUNCTIONS =====

// Generate JWT Token
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET || 'mega-services-secret', {
        expiresIn: '30d'
    });
};

// ===== ROUTES =====

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Mega Services API is running',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', [
    body('name').trim().isLength({ min: 2 }).withMessage('الاسم يجب أن يكون على الأقل حرفين'),
    body('email').isEmail().withMessage('البريد الإلكتروني غير صحيح'),
    body('password').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل'),
    body('phone').matches(/^01[0-2,5]{1}[0-9]{8}$/).withMessage('رقم الهاتف غير صحيح')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير صحيحة',
                errors: errors.array()
            });
        }

        const { name, email, password, phone } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'البريد الإلكتروني مسجل مسبقاً'
            });
        }

        // Create user
        const user = new User({
            name,
            email,
            password,
            phone
        });

        await user.save();

        // Generate token
        const token = generateToken(user._id);

        res.status(201).json({
            success: true,
            message: 'تم إنشاء الحساب بنجاح',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone,
                    role: user.role
                },
                token
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Login
app.post('/api/auth/login', [
    body('email').isEmail().withMessage('البريد الإلكتروني غير صحيح'),
    body('password').exists().withMessage('كلمة المرور مطلوبة')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير صحيحة',
                errors: errors.array()
            });
        }

        const { email, password } = req.body;

        // Find user and include password
        const user = await User.findOne({ email }).select('+password');
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
            });
        }

        if (!user.isActive) {
            return res.status(401).json({
                success: false,
                message: 'الحساب معطل. يرجى التواصل مع الإدارة'
            });
        }

        // Check password
        const isPasswordMatch = await user.comparePassword(password);
        if (!isPasswordMatch) {
            return res.status(401).json({
                success: false,
                message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
            });
        }

        // Generate token
        const token = generateToken(user._id);

        res.json({
            success: true,
            message: 'تم تسجيل الدخول بنجاح',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone,
                    role: user.role,
                    preferences: user.preferences
                },
                token
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Get Current User
app.get('/api/auth/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json({
            success: true,
            data: { user }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Update Profile
app.put('/api/auth/profile', auth, [
    body('name').optional().trim().isLength({ min: 2 }).withMessage('الاسم يجب أن يكون على الأقل حرفين'),
    body('phone').optional().matches(/^01[0-2,5]{1}[0-9]{8}$/).withMessage('رقم الهاتف غير صحيح')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير صحيحة',
                errors: errors.array()
            });
        }

        const { name, phone, preferences } = req.body;
        
        const updateData = {};
        if (name) updateData.name = name;
        if (phone) updateData.phone = phone;
        if (preferences) updateData.preferences = preferences;

        const user = await User.findByIdAndUpdate(
            req.user.id,
            updateData,
            { new: true, runValidators: true }
        );

        res.json({
            success: true,
            message: 'تم تحديث الملف الشخصي بنجاح',
            data: { user }
        });

    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// ===== BOOKING ROUTES =====

// Create Booking
app.post('/api/bookings', auth, [
    body('serviceType').isIn(['resort', 'dining', 'tour', 'spa', 'package']).withMessage('نوع الخدمة غير صحيح'),
    body('checkIn').isISO8601().withMessage('تاريخ الوصول غير صحيح'),
    body('checkOut').isISO8601().withMessage('تاريخ المغادرة غير صحيح'),
    body('adults').isInt({ min: 1, max: 10 }).withMessage('عدد البالغين يجب أن يكون بين 1 و 10'),
    body('children').isInt({ min: 0, max: 5 }).withMessage('عدد الأطفال يجب أن يكون بين 0 و 5'),
    body('guestInfo.name').notEmpty().withMessage('اسم الضيف مطلوب'),
    body('guestInfo.email').isEmail().withMessage('البريد الإلكتروني غير صحيح'),
    body('guestInfo.phone').notEmpty().withMessage('رقم الهاتف مطلوب')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير صحيحة',
                errors: errors.array()
            });
        }

        const {
            serviceType,
            checkIn,
            checkOut,
            adults,
            children,
            guestInfo,
            specialRequests
        } = req.body;

        // Check dates
        const checkInDate = new Date(checkIn);
        const checkOutDate = new Date(checkOut);
        
        if (checkOutDate <= checkInDate) {
            return res.status(400).json({
                success: false,
                message: 'تاريخ المغادرة يجب أن يكون بعد تاريخ الوصول'
            });
        }

        // Service pricing (simplified - in real app, get from Service collection)
        const servicePrices = {
            resort: 250,
            dining: 120,
            tour: 75,
            spa: 200,
            package: 350
        };

        const basePrice = servicePrices[serviceType] || 250;
        const totalNights = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));
        const baseAmount = basePrice * totalNights * adults;
        const childrenAmount = basePrice * totalNights * children * 0.5;
        const taxAmount = (baseAmount + childrenAmount) * 0.14;
        const totalAmount = baseAmount + childrenAmount + taxAmount;

        // Create booking
        const booking = new Booking({
            user: req.user.id,
            serviceType,
            serviceDetails: {
                name: getServiceName(serviceType),
                description: getServiceDescription(serviceType),
                basePrice: basePrice
            },
            checkIn: checkInDate,
            checkOut: checkOutDate,
            guests: {
                adults,
                children
            },
            guestInfo: {
                name: guestInfo.name,
                email: guestInfo.email,
                phone: guestInfo.phone,
                specialRequests: guestInfo.specialRequests || ''
            },
            pricing: {
                baseAmount,
                taxAmount,
                discountAmount: 0,
                totalAmount,
                currency: 'USD'
            },
            specialRequests: specialRequests || ''
        });

        await booking.save();
        await booking.populate('user', 'name email phone');

        res.status(201).json({
            success: true,
            message: 'تم إنشاء الحجز بنجاح',
            data: { booking }
        });

    } catch (error) {
        console.error('Create booking error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Get User Bookings
app.get('/api/bookings', auth, async (req, res) => {
    try {
        const { page = 1, limit = 10, status } = req.query;
        
        const filter = { user: req.user.id };
        if (status) filter.status = status;

        const bookings = await Booking.find(filter)
            .populate('user', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Booking.countDocuments(filter);

        res.json({
            success: true,
            data: {
                bookings,
                totalPages: Math.ceil(total / limit),
                currentPage: parseInt(page),
                total
            }
        });

    } catch (error) {
        console.error('Get bookings error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Get Single Booking
app.get('/api/bookings/:id', auth, async (req, res) => {
    try {
        const booking = await Booking.findOne({
            _id: req.params.id,
            user: req.user.id
        }).populate('user', 'name email phone');

        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'الحجز غير موجود'
            });
        }

        res.json({
            success: true,
            data: { booking }
        });

    } catch (error) {
        console.error('Get booking error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Cancel Booking
app.put('/api/bookings/:id/cancel', auth, async (req, res) => {
    try {
        const booking = await Booking.findOne({
            _id: req.params.id,
            user: req.user.id
        });

        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'الحجز غير موجود'
            });
        }

        if (booking.status === 'cancelled') {
            return res.status(400).json({
                success: false,
                message: 'الحجز ملغي بالفعل'
            });
        }

        if (booking.status === 'completed') {
            return res.status(400).json({
                success: false,
                message: 'لا يمكن إلغاء حجز مكتمل'
            });
        }

        // Calculate refund
        const refundAmount = booking.calculateRefund();

        booking.status = 'cancelled';
        booking.paymentStatus = refundAmount < booking.pricing.totalAmount ? 'partially_refunded' : 'refunded';
        booking.cancellation = {
            isCancelled: true,
            cancelledAt: new Date(),
            cancellationReason: req.body.reason || 'طلب من العميل',
            refundAmount
        };

        await booking.save();

        res.json({
            success: true,
            message: 'تم إلغاء الحجز بنجاح',
            data: { 
                booking,
                refundAmount 
            }
        });

    } catch (error) {
        console.error('Cancel booking error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// ===== SERVICE ROUTES =====

// Get All Services
app.get('/api/services', async (req, res) => {
    try {
        const { category, type } = req.query;
        
        const filter = { isActive: true };
        if (category) filter.category = category;
        if (type) filter.type = type;

        const services = await Service.find(filter).sort({ createdAt: -1 });

        res.json({
            success: true,
            data: { services }
        });

    } catch (error) {
        console.error('Get services error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Get Single Service
app.get('/api/services/:id', async (req, res) => {
    try {
        const service = await Service.findOne({
            _id: req.params.id,
            isActive: true
        });

        if (!service) {
            return res.status(404).json({
                success: false,
                message: 'الخدمة غير موجودة'
            });
        }

        res.json({
            success: true,
            data: { service }
        });

    } catch (error) {
        console.error('Get service error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// ===== ADMIN ROUTES =====

// Get All Bookings (Admin)
app.get('/api/admin/bookings', adminAuth, async (req, res) => {
    try {
        const { page = 1, limit = 20, status, serviceType } = req.query;
        
        const filter = {};
        if (status) filter.status = status;
        if (serviceType) filter.serviceType = serviceType;

        const bookings = await Booking.find(filter)
            .populate('user', 'name email phone')
            .sort({ createdAt: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);

        const total = await Booking.countDocuments(filter);

        res.json({
            success: true,
            data: {
                bookings,
                totalPages: Math.ceil(total / limit),
                currentPage: parseInt(page),
                total
            }
        });

    } catch (error) {
        console.error('Admin get bookings error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Update Booking Status (Admin)
app.put('/api/admin/bookings/:id/status', adminAuth, [
    body('status').isIn(['pending', 'confirmed', 'cancelled', 'completed', 'no_show']).withMessage('حالة غير صحيحة')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير صحيحة',
                errors: errors.array()
            });
        }

        const { status, adminNotes } = req.body;

        const booking = await Booking.findById(req.params.id);
        if (!booking) {
            return res.status(404).json({
                success: false,
                message: 'الحجز غير موجود'
            });
        }

        booking.status = status;
        if (adminNotes) booking.notes = { adminNotes };

        await booking.save();
        await booking.populate('user', 'name email phone');

        res.json({
            success: true,
            message: 'تم تحديث حالة الحجز بنجاح',
            data: { booking }
        });

    } catch (error) {
        console.error('Update booking status error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// Create Service (Admin)
app.post('/api/admin/services', adminAuth, [
    body('name').notEmpty().withMessage('اسم الخدمة مطلوب'),
    body('nameEn').notEmpty().withMessage('Service name in English is required'),
    body('category').isIn(['resort', 'dining', 'tour', 'spa', 'package']).withMessage('فئة غير صحيحة'),
    body('pricing.basePrice').isNumeric().withMessage('السعر الأساسي يجب أن يكون رقماً')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'بيانات غير صحيحة',
                errors: errors.array()
            });
        }

        const service = new Service(req.body);
        await service.save();

        res.status(201).json({
            success: true,
            message: 'تم إنشاء الخدمة بنجاح',
            data: { service }
        });

    } catch (error) {
        console.error('Create service error:', error);
        res.status(500).json({
            success: false,
            message: 'حدث خطأ في السيرفر'
        });
    }
});

// ===== HELPER FUNCTIONS =====

function getServiceName(serviceType) {
    const names = {
        resort: 'منتجع فاخر',
        dining: 'تجربة طعام راقية',
        tour: 'جولة سياحية',
        spa: 'سبا وعافية',
        package: 'باقة خاصة'
    };
    return names[serviceType] || 'خدمة';
}

function getServiceDescription(serviceType) {
    const descriptions = {
        resort: 'إقامة فاخرة في منتجعنا المطل على البحر الأحمر',
        dining: 'تجربة طهي استثنائية في مطاعمنا الحاصلة على جوائز',
        tour: 'اكتشف جمال العين السخنة مع جولاتنا المختارة',
        spa: 'تجدد في منشآت السبا الحديثة لدينا',
        package: 'باقة شاملة من أفضل الخدمات والتجارب'
    };
    return descriptions[serviceType] || 'خدمة فاخرة';
}

// ===== INITIAL DATA SETUP =====
async function initializeData() {
    try {
        // Check if admin exists
        const adminExists = await User.findOne({ email: 'admin@megaservices.com' });
        if (!adminExists) {
            const admin = new User({
                name: 'System Admin',
                email: 'admin@megaservices.com',
                password: 'admin123',
                phone: '01000000000',
                role: 'admin',
                isVerified: true
            });
            await admin.save();
            console.log('✅ Admin user created');
        }

        // Check if services exist
        const servicesCount = await Service.countDocuments();
        if (servicesCount === 0) {
            const defaultServices = [
                {
                    name: 'منتجع ديلوكس',
                    nameEn: 'Deluxe Resort',
                    description: 'غرفة فاخرة مع إطلالة على البحر وتضم أحدث وسائل الراحة',
                    descriptionEn: 'Luxurious room with sea view featuring modern amenities',
                    category: 'resort',
                    type: 'standard',
                    pricing: {
                        basePrice: 250,
                        currency: 'USD',
                        isPerPerson: false,
                        childrenDiscount: 0.5,
                        taxRate: 0.14
                    },
                    capacity: {
                        minGuests: 1,
                        maxGuests: 4
                    },
                    duration: {
                        value: 1,
                        unit: 'days'
                    },
                    features: [
                        { name: 'إطلالة على البحر', nameEn: 'Sea View', icon: '🌊', included: true },
                        { name: 'واي فاي مجاني', nameEn: 'Free WiFi', icon: '📶', included: true },
                        { name: 'مسبح خاص', nameEn: 'Private Pool', icon: '🏊', included: true }
                    ],
                    tags: ['فاخر', 'بحر', 'رومانسي']
                },
                {
                    name: 'عشاء رومانسي',
                    nameEn: 'Romantic Dinner',
                    description: 'تجربة عشاء خاصة مع إطلالة رومانسية على البحر',
                    descriptionEn: 'Private dinner experience with romantic sea view',
                    category: 'dining',
                    type: 'premium',
                    pricing: {
                        basePrice: 120,
                        currency: 'USD',
                        isPerPerson: true,
                        childrenDiscount: 0.3,
                        taxRate: 0.14
                    },
                    capacity: {
                        minGuests: 2,
                        maxGuests: 2
                    },
                    duration: {
                        value: 3,
                        unit: 'hours'
                    },
                    features: [
                        { name: 'شموع وإضاءة رومانسية', nameEn: 'Candles & Romantic Lighting', icon: '🕯️', included: true },
                        { name: 'زجاجة نبيذ', nameEn: 'Wine Bottle', icon: '🍷', included: true },
                        { name: 'طاهٍ خاص', nameEn: 'Private Chef', icon: '👨‍🍳', included: true }
                    ],
                    tags: ['رومانسي', 'عشاء', 'خاص']
                }
            ];

            await Service.insertMany(defaultServices);
            console.log('✅ Default services created');
        }
    } catch (error) {
        console.error('Data initialization error:', error);
    }
}

// ===== START SERVER =====
const PORT = process.env.PORT || 5000;

app.listen(PORT, async () => {
    console.log(`🚀 Mega Services Backend running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    
    // Initialize default data
    await initializeData();
    
    console.log('✅ Server is ready!');
    console.log('📋 Available Endpoints:');
    console.log('   GET  /api/health');
    console.log('   POST /api/auth/register');
    console.log('   POST /api/auth/login');
    console.log('   GET  /api/auth/me');
    console.log('   POST /api/bookings');
    console.log('   GET  /api/bookings');
    console.log('   GET  /api/services');
    console.log('');
    console.log('🔑 Admin Credentials:');
    console.log('   Email: admin@megaservices.com');
    console.log('   Password: admin123');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err, promise) => {
    console.log('❌ Unhandled Rejection at:', promise, 'reason:', err);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.log('❌ Uncaught Exception thrown:', err);
    process.exit(1);
});