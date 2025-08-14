
const express = require('express');
const app = express();
const PORT = 3000;
const handlebars = require('express-handlebars');
const { 
    getUserData,
    getUserByEmail,
    
    getAllCourses,
    getCourseById,
    createCourse,
    
    getAllSubjects,
    getSubjectById,
    createSubject,
    
    getStudentData,
    createStudent,
    
    getProfessorData,
    getAllProfessorData,
    getProfessorByUserId,
    createProfessor,

    getManagerData,
    createManager,
    
    getAdministratorData,
    createAdministrator,
    getAllUsers,
    deleteUser,
    updateUserRole,

    getUserPostData,
    getPostData,
    getProfPostData,
    deletePost,
    
    getPostCommentData,
    getCommentData,
    
    loginUser,
    registerUser,
    hashPassword,
    
    // Password reset functions
    generatePasswordResetToken,
    validatePasswordResetToken,
    verifySecurityQuestions,
    resetPasswordWithToken,
    resetPasswordDirectly,
    setupSecurityQuestions,
    getSecurityQuestions,
    cleanupExpiredTokens,
    validateSecurityAnswer,
    changePassword,
    reAuthenticateUser,
    
    // Account lockout functions
    recordSuccessfulLogin,
    
    // Security questions configuration
    SECURITY_QUESTIONS,
    PASSWORD_RESET_CONFIG,
    
    User,
    Student,
    Professor,
    Manager,
    Administrator,
    Course,
    Subject,
    Post,
    Comment,
    SecurityQuestions,
    PasswordResetAttempt
} = require(__dirname + '/db' + '/controller.js');

const mongoose = require('mongoose');
const session = require('express-session');
const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 15;

mongoose.connect(process.env.MONGODB_CONNECT_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err);
    console.error('   Please check your MONGODB_CONNECT_URI environment variable');
});

mongoose.connection.on('connected', async (err, res) => {
    console.log('MongoDB connected successfully!');
    
    // Initialize admin account if it doesn't exist
    try {
        await initializeAdminAccount();
        console.log('Admin account initialization completed');
    } catch (error) {
        console.error('Error initializing admin account:', error);
    }
    
    // Schedule cleanup of expired password reset tokens (every hour)
    setInterval(async () => {
        try {
            await cleanupExpiredTokens();
        } catch (error) {
            console.error('Error cleaning up expired tokens:', error);
        }
    }, 60 * 60 * 1000); // Run every hour
    
    // Initial cleanup
    try {
        await cleanupExpiredTokens();
    } catch (error) {
        console.error('Error in initial token cleanup:', error);
    }
});

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.engine('hbs', handlebars.engine({ 
    extname: 'hbs',
    helpers: {
        divide: function(a, b) {
            return Math.round(a / b);
        },
        multiply: function(a, b) {
            return a * b;
        },
        eq: function(a, b) {
            if (a == null || b == null) return false;
            return a.toString() === b.toString();
        },
        ne: function(a, b) {
            if (a == null || b == null) return false;
            return a.toString() !== b.toString();
        },
        and: function() {
            var args = Array.prototype.slice.call(arguments, 0, -1);
            return args.every(Boolean);
        },
        or: function() {
            var args = Array.prototype.slice.call(arguments, 0, -1);
            return args.some(Boolean);
        },
        ifCond: function(v1, v2, options) {
            if (v1 === v2) {
                return options.fn(this);
            }
            return options.inverse(this);
        },
        'JSON.stringify': function(obj) {
            return JSON.stringify(obj);
        },
        in: function(item, array) {
            if (!array || !Array.isArray(array)) return false;
            return array.some(function(element) {
                return element.toString() === item.toString();
            });
        }
    }
}));
app.set('view engine', 'hbs');
app.set('views', __dirname + '/views');

app.set('view cache', false);

var current;

const sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_CONNECT_URI,
    mongoOptions: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    },
    collectionName: 'sessions',
});

app.use(
    session({
        store: sessionStore,
        secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
        resave: false,
        saveUninitialized: false, // Don't create sessions for unauthenticated users
        cookie: {
            maxAge: 15 * 60 * 1000, // 15 minutes in milliseconds
            sameSite: 'strict',
            httpOnly: true, // Prevent XSS attacks
            secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        },
        name: 'profdex.sid', // Change default session name for security
        rolling: true, // Extend session on each request (within the 15-minute limit)
        unset: 'destroy' // Destroy session when unset
    })
);

app.use(async (req, res, next) => {
    // Refresh session data if user is logged in
    if (req.session.user) {
        try {
            // Check if session has been active for too long
            // Since we're using rolling sessions, we don't need to check session age
            // The session will automatically expire after 15 minutes of inactivity
            
            const currentUser = await User.findById(req.session.user._id);
            if (!currentUser) {
                // User no longer exists in database - destroy session
                console.log('Session destroyed: User no longer exists in database');
                req.session.destroy();
                res.locals.loggedInUser = null;
                return next();
            }
            
            if (currentUser.userType !== req.session.user.userType) {
                // Update the session with the current user type
                req.session.user.userType = currentUser.userType;
                console.log(`Session updated: User ${currentUser.email} role changed from ${req.session.user.userType} to ${currentUser.userType}`);
            }
            
            // Validate session data integrity
            if (!req.session.user._id || !req.session.user.email || !req.session.user.userType) {
                console.log('Session destroyed: Invalid session data');
                req.session.destroy();
                res.locals.loggedInUser = null;
                return next();
            }
            
            // Regenerate session ID periodically for security
            if (!req.session.regenerated) {
                req.session.regenerated = true;
                req.session.save();
            }
            
        } catch (error) {
            console.error('Error refreshing session:', error);
            // On database error, destroy session to fail securely
            req.session.destroy();
            res.locals.loggedInUser = null;
            return next();
        }
    }
    
    res.locals.loggedInUser = req.session.user;
    next();
});

// Import centralized authorization system
const {
    isLoggedIn,
    isStudent,
    isProfessor,
    isModerator,
    isManager,
    isAdministrator,
    hasMinimumRole,
    isResourceOwner,
    allowUserTypes,
    canPerformAction,
    canPerformActionMiddleware,
    AUTH_CONFIG,
    hasAnyRole,
    logSecurityEvent
} = require('./auth');

// Import business rules enforcement system
const {
    enforceBusinessRulesMiddleware,
    validateUserBusinessRules,
    logBusinessRuleEvent
} = require('./business_rules');

// Import data validation system
const {
    validateDataMiddleware,
    validateUserRegistration,
    validateReviewCreation,
    validateProfileEdit,
    validateSearchQuery,
    validateComment,
    validateSecurityAnswer,
    validateCourse,
    validateSubject,
    logValidationEvent
} = require('./data_validation');

async function initializeAdminAccount() {
    try {
        console.log('🔍 Checking for existing administrator account...');
        
        // Check if admin already exists
        const existingAdmin = await User.findOne({ userType: 'administrator' });
        
        if (!existingAdmin) {
            console.log('📝 No administrator found. Creating default admin account...');
            
            // Create admin user with secure password that meets all requirements
            const securePassword = 'AdminSecure2024!@#';
            const hashedPassword = await hashPassword(securePassword);
            const adminUser = new User({
                firstName: 'Admin',
                lastName: 'User',
                email: 'admin@profdex.com',
                password: hashedPassword,
                userType: 'administrator'
            });
            
            const savedAdmin = await adminUser.save();
            
            // Create administrator record
            await createAdministrator(savedAdmin._id);
            
            console.log('✅ Admin account created successfully!');
            console.log('   📧 Email: admin@profdex.com');
            console.log('   🔑 Password: AdminSecure2024!@#');
            console.log('   ⚠️  Remember to change the password after first login!');
        } else {
            console.log('ℹ️  Administrator account already exists');
        }
    } catch (error) {
        console.error('❌ Error creating admin account:', error);
        console.error('   This may affect administrator functionality');
        // Don't throw error to prevent app from crashing
    }
}

app.route('/').get(isLoggedIn, async (req, res) => {
    var data = await getAllProfessorData();
    const userType = req.session.user ? req.session.user.userType : null;
    
    // Check if we have last use information to display
    const lastUseInfo = req.session.lastUseInfo || null;
    
    res.render(__dirname + '/views' + '/home_page.hbs', {
        data,
        userType,
        loggedInUser: req.session.user,
        lastUseInfo,
        layout: false
    });
});

app.route('/createpost')
.get(isLoggedIn, async (req, res) => {
    if (req.session.user && req.session.user.userType === 'professor') {
        return res.redirect('/?error=not_allowed');
    }
    const errors = {};
    if (req.query.error === 'professor_error') {
        errors.professor_error = true;
    }
    if (req.query.error === 'validation_error') {
        errors.validation_error = true;
    }
    if (req.query.error === 'existing_review') {
        errors.existing_review = true;
    }
    if (req.query.error === 'data_validation') {
        errors.data_validation = true;
    }

    const professors = await getAllProfessorData();
    const subjects = await getAllSubjects();
    
    console.log('CreatePost - Professors found:', professors ? professors.length : 'No professors');
    console.log('CreatePost - Subjects found:', subjects ? subjects.length : 'No subjects');
    if (subjects && subjects.length > 0) {
        console.log('CreatePost - Sample subjects:', subjects.map(s => s.name));
    }
    
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/createpost.hbs', { 
        layout: false, 
        errors, 
        professors,
        subjects,
        userType
    });
})
.post(isLoggedIn, enforceBusinessRulesMiddleware('create_review', (req) => ({
    professorId: req.body.professorId,
    text: req.body.text,
    ratings: {
        generosity: req.body.generosity,
        difficulty: req.body.difficulty,
        engagement: req.body.engagement,
        proficiency: req.body.proficiency,
        workload: req.body.workload
    }
})), async (req, res) => {
    try {
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        var { professorId, course, text, generosity, difficulty, engagement, proficiency, workload} = req.body;
        
        // 2.3.1, 2.3.2, 2.3.3: Data validation before review creation
        const reviewData = {
            professorId: professorId,
            text: text,
            ratings: {
                generosity: generosity,
                difficulty: difficulty,
                engagement: engagement,
                proficiency: proficiency,
                workload: workload
            }
        };
        
        const validationResult = validateReviewCreation(reviewData);
        if (!validationResult.isValid) {
            logValidationEvent('error', 'Review creation validation failed', {
                errors: validationResult.errors,
                rejectedFields: validationResult.getRejectedFields(),
                userId: myId
            });
            
            res.redirect('/createpost?error=data_validation');
            return;
        }
        
        if (!professorId || !course || !text) {
            res.redirect('/createpost?error=validation_error');
            return;
        }
        
        var professorData = await getProfessorData(professorId);

        if (!professorData) {
            res.redirect('/createpost?error=professor_error');
            return;
        }

        const newPost = new Post({
            aPost : {
                type : Object,
                "text": text,
            },
            "op": myId,
            "to": professorData._id,
            "course": course,
            "opname": userData.firstName + " " + userData.lastName,
            "toname": professorData.userId.firstName + " " + professorData.userId.lastName,
            "generosity": generosity * 2,
            "difficulty": difficulty * 2,
            "engagement": engagement * 2,
            "proficiency": proficiency * 2,
            "workload": workload * 2
        });

        await newPost.save();

        // Log successful review creation
        logBusinessRuleEvent('info', 'Review created successfully', {
            userId: myId,
            professorId: professorData._id,
            reviewId: newPost._id
        });

        res.redirect('/reviewlist?id=' + professorData._id);
    } 
    catch (error) {
        console.error('Error saving review: ', error);
        logBusinessRuleEvent('error', 'Error creating review', {
            userId: req.session.user._id,
            error: error.message
        });
        res.redirect('/createpost?error=validation_error');
    }
});

app.route('/editprofile')
.get(isLoggedIn, async (req, res) => {
    const errors = {};
    if (req.query.error === 'validation_error') {
        errors.validation_error = true;
    }
    if (req.query.success === 'true') {
        errors.success = true;
    }
    if (req.query.password_changed === 'true') {
        errors.password_changed = true;
    }
    if (req.query.error === 'data_validation') {
        errors.data_validation = true;
    }
    
    var myId = req.session.user._id;
    var userData = await getUserData(myId);
    var studentData = null;
    var courses = null;
    var subjects = null;
    
    if (req.session.user.userType === 'student') {
        studentData = await getStudentData(myId);
        courses = await getAllCourses();
    }
    
    if (req.session.user.userType === 'professor') {
        const professorData = await getProfessorData(myId);
        subjects = await getAllSubjects();
        // Pass professor's selected subjects separately
        var professorSubjects = professorData ? professorData.subjects : [];
    }
    
    var postData = await getUserPostData(myId);
    
    // Check if we have last use information to display
    const lastUseInfo = req.session.lastUseInfo || null;
    
    res.render(__dirname + '/views' + '/editprofile_page.hbs', {
        userData,
        studentData,
        postData,
        myId,
        errors,
        courses,
        subjects,
        professorSubjects: professorSubjects || [],
        userType: req.session.user.userType,
        lastUseInfo,
        layout: false
    });
})
.post(isLoggedIn, enforceBusinessRulesMiddleware('edit_profile', (req) => ({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    bio: req.body.bio
})), async (req, res) => {
    try {
      const myId = req.session.user._id;
      const { firstName, lastName, email, studentID, course, bio } = req.body;

      // 2.3.1, 2.3.2, 2.3.3: Data validation before profile edit
      const profileData = {
        firstName: firstName,
        lastName: lastName,
        email: email,
        bio: bio
      };
      
      const validationResult = validateProfileEdit(profileData);
      if (!validationResult.isValid) {
        logValidationEvent('error', 'Profile edit validation failed', {
          errors: validationResult.errors,
          rejectedFields: validationResult.getRejectedFields(),
          userId: myId
        });
        
        res.redirect('/editprofile?error=data_validation');
        return;
      }

      if (!firstName || !lastName || !email) {
        res.redirect('/editprofile?error=validation_error');
        return;
      }

      await User.updateOne(
        { _id: myId },
        {
          $set: {
            firstName: firstName,
            lastName: lastName,
            email: email
          }
        }
      );

      if (req.session.user.userType === 'student') {
        if (!studentID || !course) {
          res.redirect('/editprofile?error=validation_error');
          return;
        }

        await Student.updateOne(
          { userId: myId },
          {
            $set: {
              studentID: studentID,
              course: course,
              bio: bio || ''
            }
          }
        );
      }
      
      if (req.session.user.userType === 'professor') {
        const { subjects } = req.body;
        
        // Update professor subjects - if no subjects selected, set to empty array
        const subjectsToUpdate = subjects && Array.isArray(subjects) ? subjects : [];
        
          await Professor.updateOne(
            { userId: myId },
            {
              $set: {
              subjects: subjectsToUpdate
              }
            }
          );
      }

      // Log successful profile update
      logBusinessRuleEvent('info', 'Profile updated successfully', {
        userId: myId,
        userType: req.session.user.userType
      });

      res.redirect('/editprofile?success=true');
    } 
    catch (error) {
      console.error('Error updating profile: ', error);
      logBusinessRuleEvent('error', 'Error updating profile', {
        userId: req.session.user._id,
        error: error.message
      });
      res.redirect('/editprofile?error=validation_error');
    }
});


app.route('/login')
.get(async (req, res) => {
    const errors = {};
    if (req.query.error === 'password_mismatch') {
        errors.password_mismatch = true;
    }
    if (req.query.error === 'authentication_failed') {
        errors.authentication_failed = true;
    }
    if (req.query.error === 'registration_error') {
        errors.registration_error = true;
    }
    if (req.query.error === 'password_validation') {
        errors.password_validation = true;
        errors.password_validation_details = req.query.details ? decodeURIComponent(req.query.details) : '';
    }
    if (req.query.error === 'invalid_data') {
        errors.invalid_data = true;
    }
    if (req.query.error === 'account_locked') {
        errors.account_locked = true;
        errors.account_locked_reason = req.query.reason ? decodeURIComponent(req.query.reason) : 'Account is locked due to too many failed login attempts.';
    }
    if (req.query.error === 'data_validation') {
        errors.data_validation = true;
        errors.data_validation_details = req.query.details ? decodeURIComponent(req.query.details) : 'Data validation failed.';
    }
    if (req.query.success === 'password_reset') {
        errors.password_reset = true;
    }
    
    const courses = await getAllCourses();
    const subjects = await getAllSubjects();
    
    res.render(__dirname + '/views' + '/LR_page.hbs', { 
        layout: false, 
        errors,
        courses,
        subjects,
        success: req.query.success // Pass success parameter to template
    });
})
.post(async (req, res) => {
    try {
        const { email, password, registerFirstName, registerLastName, registerEmail, registerPassword, confirmPassword, userType, studentID, course, teacherID, subjects } = req.body;
        
        console.log('Registration attempt:', { 
            email, 
            registerFirstName, 
            registerLastName, 
            registerEmail, 
            userType, 
            studentID, 
            course, 
            teacherID, 
            subjects 
        });

        if (email && password) {
            const loggedInUser = await loginUser(email, password, req);

            if (loggedInUser) {
                // Check for account locked error
                if (loggedInUser.error === 'account_locked') {
                    res.redirect(`/login?error=account_locked&reason=${encodeURIComponent(loggedInUser.reason)}`);
                    return;
                }

                // Check if we have last use information to display
                if (loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify) {
                    // Store last use info in session for display after redirect
                    req.session.lastUseInfo = loggedInUser.lastUseInfo;
                }

                const userType = loggedInUser.userType;
                // Redirect to original destination if available, otherwise to role-specific page
                const returnTo = req.session.returnTo;
                if (returnTo && returnTo !== '/login') {
                    delete req.session.returnTo;
                    // Add last use parameter to the redirect
                    const separator = returnTo.includes('?') ? '&' : '?';
                    const lastUseParam = loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify ? `${separator}show_last_use=true` : '';
                    res.redirect(returnTo + lastUseParam);
                } else {
                    // Redirect to role-specific page with last use parameter
                    let redirectUrl = '';
                if (userType === AUTH_CONFIG.USER_TYPES.STUDENT) {
                        redirectUrl = '/editprofile';
                } else if (userType === AUTH_CONFIG.USER_TYPES.PROFESSOR) {
                        redirectUrl = '/';
                } else if (userType === AUTH_CONFIG.USER_TYPES.MANAGER) {
                        redirectUrl = '/moderator';
                } else if (userType === AUTH_CONFIG.USER_TYPES.ADMINISTRATOR) {
                        redirectUrl = '/admin';
                } else {
                        redirectUrl = '/login?error=authentication_failed';
                    }
                    
                    // Add last use parameter if needed
                    if (loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify) {
                        const separator = redirectUrl.includes('?') ? '&' : '?';
                        redirectUrl += `${separator}show_last_use=true`;
                    }
                    
                    res.redirect(redirectUrl);
                }
            } 
            else {
                res.redirect('/login?error=authentication_failed');
                return;
            }
        } 
        else if (registerFirstName && registerLastName && registerEmail && registerPassword && confirmPassword && userType) {
            if (registerPassword !== confirmPassword) {
                res.redirect('/login?error=password_mismatch');
                return;
            }
            
            // 2.3.1, 2.3.2, 2.3.3: Data validation before registration
            const registrationData = {
                firstName: registerFirstName,
                lastName: registerLastName,
                email: registerEmail,
                userType: userType,
                studentID: studentID,
                teacherID: teacherID
            };
            
            const validationResult = validateUserRegistration(registrationData);
            if (!validationResult.isValid) {
                logValidationEvent('error', 'User registration validation failed', {
                    errors: validationResult.errors,
                    rejectedFields: validationResult.getRejectedFields()
                });
                
                // Redirect with validation error details
                const firstError = validationResult.getFirstError();
                const errorMessage = firstError ? encodeURIComponent(firstError.message) : 'Data validation failed';
                res.redirect(`/login?error=data_validation&details=${errorMessage}`);
                return;
            }
            
            let additionalData = {};
            
            if (userType === AUTH_CONFIG.USER_TYPES.STUDENT) {
                if (!studentID || !course) {
                    res.redirect('/login?error=registration_error');
                    return;
                }
                additionalData = { studentID, courseId: course };
            } else if (userType === AUTH_CONFIG.USER_TYPES.PROFESSOR) {
                if (!teacherID) {
                    res.redirect('/login?error=registration_error');
                    return;
                }
                additionalData = { teacherID, subjectIds: subjects || [] };
            }
            
            console.log('Additional data for registration:', additionalData);
            const result = await registerUser(registerFirstName, registerLastName, registerEmail, registerPassword, userType, additionalData);
            console.log('Registration result:', result);
            
            if (result.success) {
                const loggedInUser = await loginUser(registerEmail, registerPassword, req);
                if (loggedInUser) {
                    // Check if we have last use information to display
                    if (loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify) {
                        // Store last use info in session for display after redirect
                        req.session.lastUseInfo = loggedInUser.lastUseInfo;
                    }
                    
                    // Redirect to original destination if available, otherwise to role-specific page
                    const returnTo = req.session.returnTo;
                    if (returnTo && returnTo !== '/login') {
                        delete req.session.returnTo;
                        // Add last use parameter to the redirect
                        const separator = returnTo.includes('?') ? '&' : '?';
                        const lastUseParam = loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify ? `${separator}show_last_use=true` : '';
                        res.redirect(returnTo + lastUseParam);
                } else {
                        // Redirect to role-specific page with last use parameter
                        let redirectUrl = '';
                    if (userType === AUTH_CONFIG.USER_TYPES.STUDENT) {
                            redirectUrl = '/editprofile';
                    } else if (userType === AUTH_CONFIG.USER_TYPES.PROFESSOR) {
                            redirectUrl = '/';
                    } else if (userType === AUTH_CONFIG.USER_TYPES.MANAGER) {
                            redirectUrl = '/moderator';
                    } else if (userType === AUTH_CONFIG.USER_TYPES.ADMINISTRATOR) {
                            redirectUrl = '/admin';
                        }
                        
                        // Add last use parameter if needed
                        if (loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify) {
                            redirectUrl += '?show_last_use=true';
                        }
                        
                        res.redirect(redirectUrl);
                    }
                } else {
                    res.redirect('/login?error=authentication_failed');
                }
            } else {
                // Handle specific password validation errors
                if (result.error === 'Password validation failed' && result.details) {
                    const passwordErrors = result.details.join(', ');
                    res.redirect(`/login?error=password_validation&details=${encodeURIComponent(passwordErrors)}`);
            } else {
                res.redirect('/login?error=registration_error');
                }
            }
        } 
        else {
            res.redirect('/login?error=invalid_data');
        }
    } 
    catch (error) {
        console.error('Error during login/registration: ', error);
        console.error('Error stack:', error.stack);
        res.redirect('/login?error=registration_error');
    }
});

// Password reset routes
app.route('/forgot-password')
.get(async (req, res) => {
    const errors = {};
    if (req.query.error === 'user_not_found') {
        errors.user_not_found = true;
    }
    if (req.query.error === 'security_questions_not_setup') {
        errors.security_questions_not_setup = true;
    }
    if (req.query.error === 'too_many_attempts') {
        errors.too_many_attempts = true;
    }
    if (req.query.error === 'token_generation_failed') {
        errors.token_generation_failed = true;
    }
    if (req.query.success === 'token_sent') {
        errors.token_sent = true;
    }
    
    res.render(__dirname + '/views' + '/forgot_password.hbs', { 
        layout: false, 
        errors
    });
})
.post(async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            res.redirect('/forgot-password?error=user_not_found');
            return;
        }
        
        // Check if user exists and has security questions configured
        const user = await User.findOne({ email: email.toLowerCase() });
        console.log('Password reset attempt for email:', email.toLowerCase());
        console.log('User found:', !!user);
        
        if (!user) {
            console.log('User not found for email:', email.toLowerCase());
            res.redirect('/forgot-password?error=user_not_found');
            return;
        }
        
        // Check if user has security questions configured
        const securityQuestions = await SecurityQuestions.findOne({ userId: user._id });
        console.log('Security questions found:', !!securityQuestions);
        
        if (!securityQuestions) {
            console.log('Security questions not configured for user:', user._id);
            res.redirect('/forgot-password?error=security_questions_not_setup');
            return;
        }
        
        // Check for too many reset attempts
        const resetAttempts = await PasswordResetAttempt.findOne({ userId: user._id });
        if (resetAttempts && resetAttempts.attempts >= 5 && 
            (Date.now() - resetAttempts.lastAttempt) < 15 * 60 * 1000) { // 15 minutes
            res.redirect('/forgot-password?error=too_many_attempts');
            return;
        }
        
        // Redirect directly to security questions page
        res.redirect(`/reset-password?email=${encodeURIComponent(email)}`);
        
    } catch (error) {
        console.error('Error in forgot password:', error);
        // More specific error handling
        if (error.name === 'ValidationError') {
            res.redirect('/forgot-password?error=user_not_found');
        } else {
            res.redirect('/forgot-password?error=token_generation_failed');
        }
    }
});

app.route('/reset-password')
.get(async (req, res) => {
    const { email } = req.query;
    const errors = {};
    
    if (!email) {
        res.redirect('/forgot-password?error=token_generation_failed');
        return;
    }
    
    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
        res.redirect('/forgot-password?error=user_not_found');
        return;
    }
    
    // Get user's security questions
    const questionsResult = await getSecurityQuestions(user._id);
    if (!questionsResult.success) {
        res.redirect('/forgot-password?error=security_questions_not_setup');
        return;
    }
    
    if (req.query.error === 'invalid_answers') {
        errors.invalid_answers = true;
    }
    if (req.query.error === 'password_validation') {
        errors.password_validation = true;
        errors.password_validation_details = req.query.details ? decodeURIComponent(req.query.details) : '';
    }
    if (req.query.error === 'reset_failed') {
        errors.reset_failed = true;
    }
    
    res.render(__dirname + '/views' + '/reset_password.hbs', { 
        layout: false, 
        errors,
        email,
        questions: questionsResult.questions
    });
})
.post(async (req, res) => {
    try {
        const { email, answer1, answer2, answer3, newPassword, confirmPassword } = req.body;
        
        if (!email || !answer1 || !answer2 || !answer3 || !newPassword || !confirmPassword) {
            res.redirect(`/reset-password?email=${encodeURIComponent(email || '')}&error=reset_failed`);
            return;
        }
        
        // Find user by email
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            res.redirect('/forgot-password?error=user_not_found');
            return;
        }
        
        // Verify security questions
        const answers = { answer1, answer2, answer3 };
        const verificationResult = await verifySecurityQuestions(user._id, answers);
        if (!verificationResult.success) {
            res.redirect(`/reset-password?email=${encodeURIComponent(email)}&error=invalid_answers`);
            return;
        }
        
        // Check password confirmation
        if (newPassword !== confirmPassword) {
            res.redirect(`/reset-password?email=${encodeURIComponent(email)}&error=reset_failed`);
            return;
        }
        
        // Reset password directly
        const resetResult = await resetPasswordDirectly(user._id, newPassword);
        if (resetResult.success) {
            res.redirect('/login?success=password_reset');
        } else {
            if (resetResult.error === 'password_validation') {
                res.redirect(`/reset-password?email=${encodeURIComponent(email)}&error=password_validation&details=${encodeURIComponent(resetResult.details)}`);
            } else {
                res.redirect(`/reset-password?email=${encodeURIComponent(email)}&error=reset_failed`);
            }
        }
    } catch (error) {
        console.error('Error in reset password:', error);
        res.redirect(`/reset-password?email=${encodeURIComponent(req.body.email || '')}&error=reset_failed`);
    }
});

app.route('/setup-security-questions')
.get(isLoggedIn, async (req, res) => {
    const errors = {};
    if (req.query.error === 'security_question_validation') {
        errors.security_question_validation = true;
        errors.security_question_validation_details = req.query.details ? decodeURIComponent(req.query.details) : '';
    }
    if (req.query.error === 'setup_failed') {
        errors.setup_failed = true;
    }
    if (req.query.success === 'questions_setup') {
        errors.questions_setup = true;
    }
    
    res.render(__dirname + '/views' + '/setup_security_questions.hbs', { 
        layout: false, 
        errors,
        questions: SECURITY_QUESTIONS
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
        const { question1, answer1, question2, answer2, question3, answer3 } = req.body;
        
        console.log('Setup security questions POST request received');
        console.log('User ID:', req.session.user._id);
        console.log('Form data:', { question1, answer1, question2, answer2, question3, answer3 });
        
        // 2.3.1, 2.3.2, 2.3.3: Data validation for security answers
        const answers = [answer1, answer2, answer3];
        for (let i = 0; i < answers.length; i++) {
            const validationResult = validateSecurityAnswer(answers[i]);
            if (!validationResult.isValid) {
                logValidationEvent('error', 'Security answer validation failed', {
                    errors: validationResult.errors,
                    rejectedFields: validationResult.getRejectedFields(),
                    userId: req.session.user._id,
                    answerIndex: i + 1
                });
                
                res.redirect(`/setup-security-questions?error=security_question_validation&details=${encodeURIComponent(validationResult.getFirstError().message)}`);
                return;
            }
        }
        
        if (!question1 || !answer1 || !question2 || !answer2 || !question3 || !answer3) {
            console.log('Missing required fields');
            res.redirect('/setup-security-questions?error=setup_failed');
            return;
        }
        
        const questions = { question1, answer1, question2, answer2, question3, answer3 };
        console.log('Calling setupSecurityQuestions with:', questions);
        const result = await setupSecurityQuestions(req.session.user._id, questions);
        
        console.log('setupSecurityQuestions result:', result);
        
        if (result.success) {
            console.log('Security questions setup successful');
            res.redirect('/setup-security-questions?success=questions_setup');
        } else {
            console.log('Security questions setup failed:', result.error);
            if (result.error === 'security_question_validation') {
                res.redirect(`/setup-security-questions?error=security_question_validation&details=${encodeURIComponent(result.details)}`);
            } else {
                res.redirect('/setup-security-questions?error=setup_failed');
            }
        }
    } catch (error) {
        console.error('Error in setup security questions:', error);
        res.redirect('/setup-security-questions?error=setup_failed');
    }
});

app.get('/logout', isLoggedIn, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session: ', err);
        }
        res.redirect('/login');
    });
});

app.route('/reviewlist')
.get(isLoggedIn, async (req, res) => {
    var professorId = req.query.id;
    console.log('ReviewList - Professor ID:', professorId);
    
    var professorData = await getProfessorData(professorId);
    console.log('ReviewList - Professor Data:', professorData ? 'Found' : 'Not found');
    
    var postData = await getProfPostData(professorId);
    console.log('ReviewList - Post Data:', postData ? `Found ${postData.length} posts` : 'No posts found');
    if (postData && postData.length > 0) {
        console.log('ReviewList - First post sample:', {
            _id: postData[0]._id,
            op: postData[0].op,
            to: postData[0].to,
            opname: postData[0].opname
        });
    }
    
    const userType = req.session.user ? req.session.user.userType : '';
    let postUserTypes = [];
    if (postData && postData.length) {
        const userIds = postData.map(p => p.op);
        const users = await Promise.all(userIds.map(async (id) => {
            const user = await getUserData(id);
            return user ? user.userType : null;
        }));
        postUserTypes = users;
    }
    res.render(__dirname + '/views' + '/reviewlist.hbs', {
        professorData,
        postData,
        userType,
        postUserTypes,
        loggedInUser: req.session.user,
        layout: false
    });
});

app.route('/viewreview')
.get(isLoggedIn, async (req, res) => {
    try {
        var postId = req.query.id;
        var postData = await getPostData(postId);
        
        // Check if postData exists
        if (!postData) {
            return res.status(404).render(__dirname + '/views' + '/error.hbs', {
                error: 'Review not found',
                message: 'The requested review could not be found.',
                layout: false
            });
        }
        
        var professorData = null;
        if (postData && postData.to) {
            professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
        }
        var commentData = await getPostCommentData(postId);
        let commentUserTypes = [];
        if (commentData && commentData.length) {
            const userIds = commentData.map(c => c.op);
            const users = await Promise.all(userIds.map(async (id) => {
                const user = await getUserData(id);
                return user && user.userType ? user.userType : '';
            }));
            commentUserTypes = users;
        }
        const userType = req.session.user ? req.session.user.userType : null;
        res.render(__dirname + '/views' + '/viewreview.hbs', {
            professorData,
            postData,
            commentData,
            commentUserTypes,
            userType,
            loggedInUser: req.session.user,
            layout: false
        });
    } catch (error) {
        console.error('Error in /viewreview route:', error);
        res.status(500).render(__dirname + '/views' + '/error.hbs', {
            error: 'Server Error',
            message: 'An error occurred while loading the page.',
            layout: false
        });
    }
})
.post(isLoggedIn, async (req, res) => {
    try {
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        const { commentText, post, to, toname } = req.body;

        const newComment = new Comment({
            aComment : {
                text: commentText,
            },
            op: myId,
            to: to,
            post: post,
            opname: userData.firstName + ' ' + userData.lastName,
            toname: toname,
            date: new Date()
        });

        await newComment.save();

        res.redirect('/viewreview?id=' + post);
    } 
    catch (error) {
        console.error('Error saving comment: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
});

app.post('/deletecomment', isLoggedIn, async (req, res) => {
    try {
        const { commentId, postId } = req.body;
        const myId = req.session.user._id;
        const comment = await Comment.findById(commentId);
        if (!comment) {
            const msg = 'Comment not found';
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(404).json({ error: msg });
            }
            return res.redirect('/viewreview?id=' + postId);
        }
        const isManager = req.session.user && req.session.user.userType === 'manager';
        if (comment.op !== myId && !isManager) {
            const msg = 'You can only delete your own comments unless you are a manager';
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(403).json({ error: msg });
            }
            return res.redirect('/viewreview?id=' + postId);
        }
        await Comment.findByIdAndDelete(commentId);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.json({ success: true });
        }
        res.redirect('/viewreview?id=' + postId);
    } catch (error) {
        console.error('Error deleting comment:', error);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(500).json({ error: 'Server error', details: error.message });
        }
        res.redirect('/viewreview?id=' + (req.body.postId || ''));
    }
});

app.post('/delete-review-and-comments', isLoggedIn, enforceBusinessRulesMiddleware('delete_review', (req) => ({
    reviewId: req.body.reviewId
})), async (req, res) => {
    try {
        const { reviewId } = req.body;
        
        // Get the post data to check ownership
        const postData = await getPostData(reviewId);
        if (!postData) {
            return res.status(404).send('Review not found');
        }
        
        // Delete comments first, then the post
        await Comment.deleteMany({ post: reviewId });
        await deletePost(reviewId);
        
        // Log successful deletion
        logBusinessRuleEvent('info', 'Review deleted successfully', {
            userId: req.session.user._id,
            userType: req.session.user.userType,
            reviewId: reviewId,
            reviewOwner: postData.op
        });
        
        // Redirect based on user type
        if (hasAnyRole(['student', 'professor'], req.session.user)) {
            res.redirect('/editprofile');
        } else {
            res.redirect('/');
        }
    } catch (error) {
        console.error('Error deleting review and comments:', error);
        logBusinessRuleEvent('error', 'Error deleting review', {
            userId: req.session.user._id,
            userType: req.session.user.userType,
            reviewId: req.body.reviewId,
            error: error.message
        });
        res.status(500).send('Server error');
    }
});

app.route('/reply')
.get(isLoggedIn, async (req, res) => {
    var commentID = req.query.id;
    var commentData = await getCommentData(commentID);
    var userData = await getUserData(new mongoose.Types.ObjectId(commentData.op));
    res.render(__dirname + '/views' + '/reply.hbs', {
        commentData,
        userData,
        layout: false
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
        if (!req.session.user) {
            console.error('No user in session');
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(401).json({ error: 'Not logged in' });
            }
            return res.render(__dirname + '/views/error.hbs', { layout: false });
        }
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        if (!userData || !userData.firstName || !userData.lastName) {
            console.error('User data missing or malformed:', userData);
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(400).json({ error: 'User data error' });
            }
            return res.render(__dirname + '/views/error.hbs', { layout: false });
        }
        const { commentText, post, to, toname } = req.body;
        const newComment = new Comment({
            aComment : {
                text: commentText,
            },
            op: myId,
            to: to,
            post: post,
            opname: userData.firstName + ' ' + userData.lastName,
            toname: toname,
            date: new Date()
        });
        await newComment.save();
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.json({ success: true });
        }
        res.redirect('/viewreview?id=' + post);
    } 
    catch (error) {
        console.error('Error saving comment: ', error);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(500).json({ error: 'Server error', details: error.message });
        }
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
});

app.route('/viewcomments')
.get(isLoggedIn, async (req, res) => {
    try {
        var postId = req.query.id;
        var postData = await getPostData(postId);
        
        // Check if postData exists
        if (!postData) {
            return res.status(404).render(__dirname + '/views' + '/error.hbs', {
                error: 'Post not found',
                message: 'The requested post could not be found.',
                layout: false
            });
        }
        
        var professorData = null;
        if (postData && postData.to) {
            professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
        }
        var commentData = await getPostCommentData(postId);
        let commentUserTypes = [];
        if (commentData && commentData.length) {
            const userIds = commentData.map(c => c.op);
            const users = await Promise.all(userIds.map(async (id) => {
                const user = await getUserData(id);
                return user && user.userType ? user.userType : '';
            }));
            commentUserTypes = users;
        }
        const userType = req.session.user ? req.session.user.userType : null;
        res.render(__dirname + '/views' + '/viewcomments.hbs', {
            professorData,
            postData,
            commentData,
            commentUserTypes,
            userType,
            loggedInUser: req.session.user,
            layout: false
        });
    } catch (error) {
        console.error('Error in /viewcomments route:', error);
        res.status(500).render(__dirname + '/views' + '/error.hbs', {
            error: 'Server Error',
            message: 'An error occurred while loading the page.',
            layout: false
        });
    }
});

app.route('/viewprof')
.get(isLoggedIn, async (req, res) => {
    try {
        var professorId = req.query.id;
        console.log('ViewProf - Professor ID:', professorId);
        
        var professorData = await getProfessorData(professorId);
        console.log('ViewProf - Professor Data:', professorData ? 'Found' : 'Not found');
        
        var postData = await getProfPostData(professorId);
        console.log('ViewProf - Post Data:', postData ? `Found ${postData.length} posts` : 'No posts found');
        if (postData && postData.length > 0) {
            console.log('ViewProf - First post sample:', {
                _id: postData[0]._id,
                op: postData[0].op,
                to: postData[0].to,
                opname: postData[0].opname
            });
            console.log('ViewProf - Full postData structure:', JSON.stringify(postData, null, 2));
        }
        
        const templateData = {
            professorData,
            postData,
            loggedInUser: req.session.user,
            userType: req.session.user ? req.session.user.userType : null,
            layout: false
        };
        
        console.log('ViewProf - Template data being passed:', {
            professorData: templateData.professorData ? 'Found' : 'Not found',
            postDataLength: templateData.postData ? templateData.postData.length : 'No postData',
            userType: templateData.userType,
            layout: templateData.layout
        });
        
        res.render(__dirname + '/views' + '/viewprof.hbs', templateData);
    }
    catch (error) {
        console.error('ViewProf Error:', error);
        res.redirect('/login');
    }
})
.post(isLoggedIn, async (req, res) => {
    try {
        const { search } = req.body;
        
        // 2.3.1, 2.3.2, 2.3.3: Data validation for search query
        const validationResult = validateSearchQuery(search);
        if (!validationResult.isValid) {
            logValidationEvent('error', 'Search query validation failed', {
                errors: validationResult.errors,
                rejectedFields: validationResult.getRejectedFields()
            });
            
            res.redirect('/?error=invalid_search');
            return;
        }
        
        if (!search || search.trim() === '') {
            res.redirect('/');
            return;
        }
        
        // Search for professors with similar names
        const searchTerm = search.trim().toLowerCase();
        
        // Get all professors and filter by name similarity
        const allProfessors = await getAllProfessorData();
        const matchingProfessors = [];
        
        for (const prof of allProfessors) {
            const user = await getUserData(prof.userId);
            if (user) {
                const fullName = `${user.firstName} ${user.lastName}`.toLowerCase();
                if (fullName.includes(searchTerm) || 
                    user.firstName.toLowerCase().includes(searchTerm) || 
                    user.lastName.toLowerCase().includes(searchTerm)) {
                    matchingProfessors.push({
                        professor: prof,
                        user: user
                    });
                }
            }
        }
        
        // If exact match found, redirect to that professor's page
        const exactMatch = matchingProfessors.find(p => 
            `${p.user.firstName} ${p.user.lastName}`.toLowerCase() === searchTerm
        );
        
        if (exactMatch && matchingProfessors.length === 1) {
            res.redirect(`/viewprof?id=${exactMatch.professor._id}`);
            return;
        }
        
        // Otherwise, show search results page
        res.render(__dirname + '/views' + '/professor_search.hbs', {
            searchTerm: search,
            results: matchingProfessors,
            loggedInUser: req.session.user,
            userType: req.session.user ? req.session.user.userType : null,
            layout: false
        });
        
    } catch (error) {
        console.error('Search error:', error);
        res.redirect('/');
    }
})




app.route('/editreview')
.get(isLoggedIn, async (req, res) => {
    try {
        const { reviewId } = req.query;
        const myId = req.session.user._id;
        
        const reviewData = await getPostData(reviewId);
        
        if (!reviewData) {
            res.redirect('/editprofile');
            return;
        }
        
        if (reviewData.op !== myId) {
            res.redirect('/editprofile');
            return;
        }
        
        res.render(__dirname + '/views' + '/editreview.hbs', {
            reviewData,
            layout: false
        });
    } 
    catch (error) {
        console.error('Error loading review for editing: ', error);
        res.redirect('/editprofile');
    }
})
.post(isLoggedIn, async (req, res) => {
    try {
        const { reviewId, text, generosity, difficulty, engagement, proficiency, workload } = req.body;
        const myId = req.session.user._id;
        
        const reviewData = await getPostData(reviewId);
        
        if (!reviewData) {
            res.status(404).json({ error: 'Review not found' });
            return;
        }
        
        if (reviewData.op !== myId) {
            res.status(403).json({ error: 'You can only edit your own reviews' });
            return;
        }
        
        if (!text || text.length < 10) {
            res.redirect('/editreview?reviewId=' + reviewId + '&error=validation_error');
            return;
        }
        
        await Post.updateOne(
            { _id: reviewId },
            {
                $set: {
                    'aPost.text': text,
                    'generosity': generosity * 2,
                    'difficulty': difficulty * 2,
                    'engagement': engagement * 2,
                    'proficiency': proficiency * 2,
                    'workload': workload * 2
                }
            }
        );
        
        res.redirect('/editprofile?success=true');
    } 
    catch (error) {
        console.error('Error updating review: ', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.route('/help').all(isLoggedIn, async(req, res) => {
    try{

        res.render(__dirname + '/views' + '/help.hbs', { layout: false });

    }catch(error) {
        console.error('Error during help: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
})

// Moderator Routes
app.route('/moderator')
.get(isModerator, async (req, res) => {
    try {
        console.log('Moderator route accessed');
        const users = await getAllUsers();
        console.log('getAllUsers result:', users);
        
        const userType = req.session.user ? req.session.user.userType : null;
        console.log('Current user type:', userType);
        
        // Calculate user counts for statistics
        const studentCount = users.filter(user => user.userType === AUTH_CONFIG.USER_TYPES.STUDENT).length;
        const professorCount = users.filter(user => user.userType === AUTH_CONFIG.USER_TYPES.PROFESSOR).length;
        const unassignedCount = users.filter(user => hasAnyRole([AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR], user)).length;
        
        console.log('Moderator Dashboard Statistics:');
        console.log('Total users:', users.length);
        console.log('Student count:', studentCount);
        console.log('Professor count:', professorCount);
        console.log('Unassigned count:', unassignedCount);
        console.log('User types found:', users.map(u => u.userType));
        
        const templateData = {
            users,
            userType,
            studentCount,
            professorCount,
            unassignedCount,
            lastUseInfo: req.session.lastUseInfo || null,
            layout: false
        };
        
        console.log('Template data being passed:', templateData);
        
        res.render(__dirname + '/views' + '/moderator_dashboard.hbs', templateData);
    } catch (error) {
        console.error('Error loading moderator dashboard: ', error);
        res.status(500).send('Server error');
    }
});

app.route('/moderator/users')
.get(isModerator, async (req, res) => {
    try {
        const users = await getAllUsers();
        res.json(users);
    } catch (error) {
        console.error('Error fetching users: ', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/moderator/update-role', isModerator, async (req, res) => {
    try {
        const { userId, newRole } = req.body;
        
        // Moderators can only assign student or professor roles
        if (newRole !== 'student' && newRole !== 'professor') {
            return res.status(403).json({ error: 'Moderators can only assign student or professor roles' });
        }
        
        const result = await updateUserRole(userId, newRole);
        
        if (result) {
            res.json({ success: true, message: 'User role updated successfully' });
        } else {
            res.status(500).json({ error: 'Failed to update user role' });
        }
    } catch (error) {
        console.error('Error updating user role: ', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Administrator Routes
app.route('/admin')
.get(isAdministrator, async (req, res) => {
    try {
        const users = await getAllUsers();
        const userType = req.session.user ? req.session.user.userType : null;
        
        // Calculate user counts for statistics
        const studentCount = users.filter(user => user.userType === AUTH_CONFIG.USER_TYPES.STUDENT).length;
        const professorCount = users.filter(user => user.userType === AUTH_CONFIG.USER_TYPES.PROFESSOR).length;
        const moderatorCount = users.filter(user => user.userType === AUTH_CONFIG.USER_TYPES.MANAGER).length;
        
        res.render(__dirname + '/views' + '/admin_dashboard.hbs', {
            users,
            userType,
            studentCount,
            professorCount,
            moderatorCount,
            lastUseInfo: req.session.lastUseInfo || null,
            layout: false
        });
    } catch (error) {
        console.error('Error loading admin dashboard: ', error);
        res.status(500).send('Server error');
    }
});

app.route('/admin/users')
.get(isAdministrator, async (req, res) => {
    try {
        const users = await getAllUsers();
        res.json(users);
    } catch (error) {
        console.error('Error fetching users: ', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.route('/admin/logs')
.get(isAdministrator, async (req, res) => {
    try {
        res.render(__dirname + '/views' + '/admin_logs.hbs', {
            layout: false
        });
    } catch (error) {
        console.error('Error loading admin logs: ', error);
        res.status(500).send('Server error');
    }
});

app.post('/admin/delete-user', canPerformActionMiddleware('delete_user'), async (req, res) => {
    try {
        console.log('Full request body:', req.body);
        const { userId } = req.body;
        console.log('Admin attempting to delete user:', userId);
        console.log('userId type:', typeof userId);
        console.log('userId value:', userId);
        
        if (!userId) {
            console.log('No userId provided');
            return res.status(400).json({ error: 'User ID is required' });
        }
        
        // Additional fail-secure validation: prevent self-deletion
        if (userId === req.session.user._id.toString()) {
            logSecurityEvent('warn', 'Admin attempted to delete their own account', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                userId: req.session.user._id,
                userType: req.session.user.userType
            });
            return res.status(403).json({ error: 'Cannot delete your own account' });
        }
        
        const result = await deleteUser(userId);
        
        if (result) {
            console.log('User deletion successful:', result.email);
            logSecurityEvent('info', 'User deleted successfully', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                adminUserId: req.session.user._id,
                adminUserType: req.session.user.userType,
                deletedUserId: userId,
                deletedUserEmail: result.email
            });
            res.json({ success: true, message: 'User deleted successfully' });
        } else {
            console.log('User deletion failed - no result returned');
            res.status(500).json({ error: 'Failed to delete user - user may not exist' });
        }
    } catch (error) {
        console.error('Error deleting user: ', error);
        logSecurityEvent('error', 'Error deleting user', {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            adminUserId: req.session.user._id,
            adminUserType: req.session.user.userType,
            targetUserId: req.body.userId,
            error: error.message
        });
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.post('/admin/update-role', canPerformActionMiddleware('update_user_role'), async (req, res) => {
    try {
        const { userId, newRole } = req.body;
        console.log(`Admin attempting to update user ${userId} to role: ${newRole}`);
        
        if (!userId || !newRole) {
            return res.status(400).json({ error: 'User ID and new role are required' });
        }
        
        // Additional fail-secure validation: validate role
        const validRoles = Object.values(AUTH_CONFIG.USER_TYPES);
        if (!validRoles.includes(newRole)) {
            logSecurityEvent('warn', 'Invalid role update attempt', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                adminUserId: req.session.user._id,
                adminUserType: req.session.user.userType,
                targetUserId: userId,
                invalidRole: newRole,
                validRoles
            });
            return res.status(400).json({ error: 'Invalid role specified' });
        }
        
        // Additional fail-secure validation: prevent self-role-change
        if (userId === req.session.user._id.toString()) {
            logSecurityEvent('warn', 'Admin attempted to change their own role', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                userId: req.session.user._id,
                userType: req.session.user.userType,
                attemptedRole: newRole
            });
            return res.status(403).json({ error: 'Cannot change your own role' });
        }
        
        const result = await updateUserRole(userId, newRole);
        
        if (result) {
            console.log(`Successfully updated user ${userId} to role: ${newRole}`);
            logSecurityEvent('info', 'User role updated successfully', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                adminUserId: req.session.user._id,
                adminUserType: req.session.user.userType,
                targetUserId: userId,
                oldRole: result.userType,
                newRole: newRole
            });
            res.json({ success: true, message: 'User role updated successfully' });
        } else {
            console.log(`Failed to update user ${userId} to role: ${newRole}`);
            res.status(500).json({ error: 'Failed to update user role - please try again' });
        }
    } catch (error) {
        console.error('Error updating user role: ', error);
        logSecurityEvent('error', 'Error updating user role', {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            adminUserId: req.session.user._id,
            adminUserType: req.session.user.userType,
            targetUserId: req.body.userId,
            attemptedRole: req.body.newRole,
            error: error.message
        });
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.route('/admin/login')
.get(async (req, res) => {
    try {
        console.log('Admin login GET request received');
    const errors = {};
        if (req.query.error === 'authentication_failed') {
            errors.authentication_failed = true;
        }
        if (req.query.error === 'account_locked') {
            errors.account_locked = true;
            errors.account_locked_reason = req.query.reason ? decodeURIComponent(req.query.reason) : 'Account is locked due to too many failed login attempts.';
        }
        
        // Store the original URL to redirect back after login
        if (req.query.returnTo) {
            req.session.returnTo = req.query.returnTo;
        }
        
        console.log('Rendering admin login page with errors:', errors);
    res.render(__dirname + '/views' + '/admin_login.hbs', { 
        layout: false, 
        errors
    });
    } catch (error) {
        console.error('Error in admin login GET route:', error);
        res.status(500).send('Internal server error');
    }
})
.post(async (req, res) => {
    try {
        console.log('Admin login POST request received');
        const { email, password } = req.body;
        
        if (!email || !password) {
            console.log('Admin login failed: Missing email or password');
            return res.redirect('/admin/login?error=authentication_failed');
        }
        
        console.log('Attempting admin login for email:', email);
        const loggedInUser = await loginUser(email, password, req);
        
        if (loggedInUser) {
            // Check for account locked error
            if (loggedInUser.error === 'account_locked') {
                console.log('Admin login blocked: Account locked');
                res.redirect(`/admin/login?error=account_locked&reason=${encodeURIComponent(loggedInUser.reason)}`);
                return;
            }
            
            if (canPerformAction(loggedInUser, 'view_admin_panel')) {
                console.log('Admin login successful for:', email);
                // Check if we have last use information to display
                if (loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify) {
                    // Store last use info in session for display after redirect
                    req.session.lastUseInfo = loggedInUser.lastUseInfo;
                }
                
                // Redirect to original destination if available, otherwise to admin dashboard
                const returnTo = req.session.returnTo;
                if (returnTo && returnTo !== '/admin/login') {
                    delete req.session.returnTo;
                    // Add last use parameter to the redirect
                    const separator = returnTo.includes('?') ? '&' : '?';
                    const lastUseParam = loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify ? `${separator}show_last_use=true` : '';
                    res.redirect(returnTo + lastUseParam);
        } else {
                    // Redirect to admin dashboard with last use parameter if needed
                    let redirectUrl = '/admin';
                    if (loggedInUser.lastUseInfo && loggedInUser.lastUseInfo.shouldNotify) {
                        redirectUrl += '?show_last_use=true';
                    }
                    res.redirect(redirectUrl);
                }
            } else {
                console.log('Admin login failed: User is not administrator');
                res.redirect('/admin/login?error=authentication_failed');
            }
        } else {
            console.log('Admin login failed: Invalid credentials');
            res.redirect('/admin/login?error=authentication_failed');
        }
    } catch (error) {
        console.error('Error during admin login: ', error);
        res.redirect('/admin/login?error=authentication_failed');
    }
});

// Password change request route (Step 1: Re-authentication)
app.route('/change-password-request')
.get(isLoggedIn, (req, res) => {
    const errors = {};
    if (req.query.error === 'reauth_failed') {
        errors.reauth_failed = true;
    }
    if (req.query.error === 'account_locked') {
        errors.account_locked = true;
        errors.lockout_message = req.query.message ? decodeURIComponent(req.query.message) : '';
    }
    if (req.query.error === 'reauth_expired') {
        errors.reauth_expired = true;
    }
    
    res.render(__dirname + '/views' + '/change_password_request.hbs', { 
        layout: false, 
        errors,
        userType: req.session.user.userType,
        loggedInUser: req.session.user
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
        console.log('=== Change Password Request POST ===');
        console.log('Request body:', req.body);
        console.log('Session user ID:', req.session.user._id);
        console.log('Session user email:', req.session.user.email);
        
        const { currentPassword } = req.body;
        
        // Validate input
        if (!currentPassword) {
            console.log('Missing currentPassword in request body');
            res.redirect('/change-password-request?error=reauth_failed');
            return;
        }
        
        console.log('Attempting re-authentication...');
        
        // Re-authenticate user
        const reAuthResult = await reAuthenticateUser(req.session.user._id, currentPassword);
        console.log('Re-authentication result:', reAuthResult);
        
        if (reAuthResult.success) {
            // Store re-authentication status in session
            req.session.reauthenticated = true;
            req.session.reauthTimestamp = Date.now();
            req.session.save();
            
            console.log('Re-authentication successful, redirecting to password change form');
            // Redirect to password change form
            res.redirect('/change-password');
        } else {
            console.log('Re-authentication failed:', reAuthResult.error);
            if (reAuthResult.error.includes('locked')) {
                const message = encodeURIComponent(reAuthResult.error);
                res.redirect(`/change-password-request?error=account_locked&message=${message}`);
            } else {
                res.redirect('/change-password-request?error=reauth_failed');
            }
        }
    } catch (error) {
        console.error('Error during re-authentication:', error);
        res.redirect('/change-password-request?error=reauth_failed');
    }
});

// Password change route (Step 2: Actual password change)
app.route('/change-password')
.get(isLoggedIn, async (req, res) => {
    // Check if user has been re-authenticated
    if (!req.session.reauthenticated || !req.session.reauthTimestamp) {
        return res.redirect('/change-password-request');
    }
    
    // Check if re-authentication is still valid (15 minutes)
    const reauthAge = Date.now() - req.session.reauthTimestamp;
    const reauthTimeout = 15 * 60 * 1000; // 15 minutes
    
    if (reauthAge > reauthTimeout) {
        // Clear expired re-authentication
        delete req.session.reauthenticated;
        delete req.session.reauthTimestamp;
        return res.redirect('/change-password-request?error=reauth_expired');
    }
    
    const errors = {};
    if (req.query.error === 'validation_error') {
        errors.validation_error = true;
    }
    if (req.query.error === 'current_password_error') {
        errors.current_password_error = true;
    }
    if (req.query.error === 'password_history_error') {
        errors.password_history_error = true;
    }
    if (req.query.error === 'password_validation_error') {
        errors.password_validation_error = true;
        errors.password_validation_details = req.query.details ? decodeURIComponent(req.query.details) : '';
    }
    if (req.query.error === 'password_age_error') {
        errors.password_age_error = true;
        errors.password_age_message = req.query.message ? decodeURIComponent(req.query.message) : '';
    }
    if (req.query.success === 'true') {
        errors.success = true;
    }
    
    res.render(__dirname + '/views' + '/change_password.hbs', { 
        layout: false, 
        errors,
        userType: req.session.user.userType,
        loggedInUser: req.session.user
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
        console.log('Change password POST request received');
        console.log('Request body:', req.body);
        console.log('Session user:', req.session.user ? req.session.user._id : 'No user');
        console.log('Re-authenticated status:', req.session.reauthenticated);
        
        const { currentPassword, newPassword, confirmPassword } = req.body;
        
        // Validate input
        if (!currentPassword || !newPassword || !confirmPassword) {
            console.log('Missing required fields - currentPassword:', !!currentPassword, 'newPassword:', !!newPassword, 'confirmPassword:', !!confirmPassword);
            res.redirect('/change-password?error=validation_error');
            return;
        }
        
        // Check if passwords match
        if (newPassword !== confirmPassword) {
            res.redirect('/change-password?error=validation_error');
            return;
        }
        
        // Always require re-authentication for password changes
        console.log('Calling changePassword function...');
        const result = await changePassword(req.session.user._id, currentPassword, newPassword);
        console.log('changePassword result:', result);
        
        if (result.success) {
            // Clear re-authentication status after successful password change
            delete req.session.reauthenticated;
            delete req.session.reauthTimestamp;
            res.redirect('/editprofile?password_changed=true');
        } else {
            if (result.error.includes('used recently')) {
                res.redirect('/change-password?error=password_history_error');
            } else if (result.error === 'Password validation failed') {
                const details = encodeURIComponent(result.details.join(', '));
                res.redirect(`/change-password?error=password_validation_error&details=${details}`);
            } else if (result.error.includes('must be at least') && result.error.includes('day(s) old')) {
                const message = encodeURIComponent(result.error);
                res.redirect(`/change-password?error=password_age_error&message=${message}`);
            } else {
                res.redirect('/change-password?error=validation_error');
            }
        }
    } catch (error) {
        console.error('Error changing password:', error);
        res.redirect('/change-password?error=validation_error');
    }
});

// Global error handler for authentication failures
app.use((err, req, res, next) => {
    console.error('Global error handler:', err);
    
    // Handle authentication-related errors
    if (err.name === 'UnauthorizedError' || err.status === 401) {
        if (req.session) {
            req.session.destroy();
        }
        return res.redirect('/login');
    }
    
    // Handle other errors
    res.status(500).render(__dirname + '/views' + '/error.hbs', {
        error: 'Server Error',
        message: 'An unexpected error occurred.',
        layout: false
    });
});

// 404 handler - fail securely by redirecting to login
app.use((req, res) => {
    console.log('404 - Route not found:', req.originalUrl);
    res.redirect('/login');
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port: ${PORT}`);
    console.log(`📱 Access your application at: http://localhost:${PORT}`);
    console.log(`🔐 Admin panel available at: http://localhost:${PORT}/admin/login`);
    console.log(`🔑 Current password pepper: ${process.env.PASSWORD_PEPPER || 'default-pepper-change-in-production'}`);
});

module.exports = app;