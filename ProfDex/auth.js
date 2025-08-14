/**
 * Centralized Authorization System for ProfDex
 * 
 * This file implements requirement 2.2.1: Use a single site-wide component to check access authorization
 * AND requirement 2.2.2: Access controls should fail securely
 * 
 * All authorization logic is centralized here to ensure consistency, maintainability,
 * and security across the entire application. The system implements fail-secure principles
 * where access is denied by default unless explicitly permitted.
 */

const { User } = require('./db/controller');

/**
 * Authorization Configuration
 */
const AUTH_CONFIG = {
    // User types and their hierarchy
    USER_TYPES: {
        STUDENT: 'student',
        PROFESSOR: 'professor', 
        MANAGER: 'manager',
        ADMINISTRATOR: 'administrator'
    },
    
    // Role hierarchy (higher numbers = more privileges)
    ROLE_HIERARCHY: {
        'student': 1,
        'professor': 2,
        'manager': 3,
        'administrator': 4
    },
    
    // Session validation settings
    SESSION_VALIDATION: {
        REQUIRED_FIELDS: ['_id', 'email', 'userType'],
        REDIRECT_URLS: {
            DEFAULT: '/login',
            ADMIN: '/admin/login',
            MODERATOR: '/login'
        }
    },
    
    // Fail-secure configuration
    FAIL_SECURE: {
        LOG_ACCESS_ATTEMPTS: true,
        LOG_FAILED_ATTEMPTS: true,
        LOG_SUSPICIOUS_ACTIVITY: true,
        SUSPICIOUS_ACTIVITY_THRESHOLD: 3, // Number of failed attempts before logging as suspicious
        ERROR_MESSAGES: {
            ACCESS_DENIED: 'Access denied. You do not have permission to perform this action.',
            SESSION_INVALID: 'Your session is invalid or has expired. Please log in again.',
            UNAUTHORIZED: 'Unauthorized access attempt.',
            INSUFFICIENT_PRIVILEGES: 'Insufficient privileges for this operation.'
        }
    }
};

/**
 * Security logging function for fail-secure monitoring
 * @param {string} level - Log level (info, warn, error, security)
 * @param {string} message - Log message
 * @param {Object} context - Additional context (user, action, resource, etc.)
 */
function logSecurityEvent(level, message, context = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        level,
        message,
        context: {
            ...context,
            userAgent: context.userAgent || 'Unknown',
            ipAddress: context.ipAddress || 'Unknown',
            sessionId: context.sessionId || 'Unknown'
        }
    };
    
    // Log to console for development/debugging
    console.log(`[SECURITY ${level.toUpperCase()}] ${timestamp}: ${message}`, logEntry.context);
    
    // In production, this would be logged to a secure logging system
    // TODO: Implement secure logging to file or external service
}

/**
 * Enhanced base authorization middleware that validates session integrity with fail-secure principles
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object  
 * @param {Function} next - Express next function
 * @returns {void}
 */
function validateSession(req, res, next) {
    // Fail securely - deny access by default
    if (!req.session || !req.session.user) {
        // Log the access attempt
        if (AUTH_CONFIG.FAIL_SECURE.LOG_ACCESS_ATTEMPTS) {
            logSecurityEvent('warn', 'Access attempt without valid session', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                requestedUrl: req.originalUrl,
                method: req.method
            });
        }
        
        // Store the original URL to redirect back after login
        if (req.session) {
            req.session.returnTo = req.originalUrl;
        }
        
        return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
    }
    
    // Validate session integrity - ensure all required fields exist
    const user = req.session.user;
    const missingFields = AUTH_CONFIG.SESSION_VALIDATION.REQUIRED_FIELDS.filter(field => !user[field]);
    
    if (missingFields.length > 0) {
        // Log suspicious activity - invalid session data
        if (AUTH_CONFIG.FAIL_SECURE.LOG_SUSPICIOUS_ACTIVITY) {
            logSecurityEvent('error', 'Invalid session data detected', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                requestedUrl: req.originalUrl,
                method: req.method,
                sessionId: req.sessionID,
                missingFields,
                sessionData: { ...user, password: '[REDACTED]' }
            });
        }
        
        console.log(`Invalid session data detected, missing fields: ${missingFields.join(', ')}`);
        req.session.destroy();
        return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
    }
    
    // Validate user type is in allowed list
    if (!Object.values(AUTH_CONFIG.USER_TYPES).includes(user.userType)) {
        if (AUTH_CONFIG.FAIL_SECURE.LOG_SUSPICIOUS_ACTIVITY) {
            logSecurityEvent('error', 'Invalid user type in session', {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                requestedUrl: req.originalUrl,
                method: req.method,
                sessionId: req.sessionID,
                invalidUserType: user.userType,
                userId: user._id
            });
        }
        
        req.session.destroy();
        return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
    }
    
    next();
}

/**
 * Enhanced role checking with fail-secure validation
 * @param {string} requiredRole - Minimum required role
 * @param {Object} user - User object from session
 * @returns {boolean} - True if user has sufficient privileges
 */
function hasRoleLevel(requiredRole, user) {
    // Fail securely - deny access if user data is invalid
    if (!user || !user.userType) {
        return false;
    }
    
    // Validate that the required role exists
    if (!AUTH_CONFIG.ROLE_HIERARCHY[requiredRole]) {
        console.error(`Invalid required role: ${requiredRole}`);
        return false;
    }
    
    // Validate that the user's role exists
    if (!AUTH_CONFIG.ROLE_HIERARCHY[user.userType]) {
        console.error(`Invalid user role: ${user.userType}`);
        return false;
    }
    
    const userLevel = AUTH_CONFIG.ROLE_HIERARCHY[user.userType] || 0;
    const requiredLevel = AUTH_CONFIG.ROLE_HIERARCHY[requiredRole] || 0;
    
    return userLevel >= requiredLevel;
}

/**
 * Enhanced exact role checking with fail-secure validation
 * @param {string} exactRole - Exact role required
 * @param {Object} user - User object from session
 * @returns {boolean} - True if user has exact role
 */
function hasExactRole(exactRole, user) {
    // Fail securely - deny access if user data is invalid
    if (!user || !user.userType) {
        return false;
    }
    
    // Validate that the required role exists
    if (!AUTH_CONFIG.ROLE_HIERARCHY[exactRole]) {
        console.error(`Invalid exact role: ${exactRole}`);
        return false;
    }
    
    return user.userType === exactRole;
}

/**
 * Enhanced role checking with fail-secure validation
 * @param {Array<string>} allowedRoles - Array of allowed roles
 * @param {Object} user - User object from session
 * @returns {boolean} - True if user has any of the allowed roles
 */
function hasAnyRole(allowedRoles, user) {
    // Fail securely - deny access if user data is invalid
    if (!user || !user.userType) {
        return false;
    }
    
    // Validate that allowedRoles is an array
    if (!Array.isArray(allowedRoles)) {
        console.error('hasAnyRole: allowedRoles must be an array');
        return false;
    }
    
    // Validate that all roles in allowedRoles exist
    const invalidRoles = allowedRoles.filter(role => !AUTH_CONFIG.ROLE_HIERARCHY[role]);
    if (invalidRoles.length > 0) {
        console.error(`Invalid roles in allowedRoles: ${invalidRoles.join(', ')}`);
        return false;
    }
    
    return allowedRoles.includes(user.userType);
}

/**
 * Enhanced authorization middleware for basic authentication with fail-secure logging
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isLoggedIn(req, res, next) {
    validateSession(req, res, next);
}

/**
 * Enhanced authorization middleware for students only with fail-secure logging
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isStudent(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.STUDENT, req.session.user)) {
            // Log failed access attempt
            if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                logSecurityEvent('warn', 'Student-only access denied', {
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    requestedUrl: req.originalUrl,
                    method: req.method,
                    sessionId: req.sessionID,
                    userId: req.session.user._id,
                    userType: req.session.user.userType
                });
            }
            
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Enhanced authorization middleware for professors only with fail-secure logging
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isProfessor(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.PROFESSOR, req.session.user)) {
            // Log failed access attempt
            if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                logSecurityEvent('warn', 'Professor-only access denied', {
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    requestedUrl: req.originalUrl,
                    method: req.method,
                    sessionId: req.sessionID,
                    userId: req.session.user._id,
                    userType: req.session.user.userType
                });
            }
            
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Enhanced authorization middleware for moderators with fail-secure logging
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isModerator(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasAnyRole([AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR], req.session.user)) {
            // Log failed access attempt
            if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                logSecurityEvent('warn', 'Moderator access denied', {
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    requestedUrl: req.originalUrl,
                    method: req.method,
                    sessionId: req.sessionID,
                    userId: req.session.user._id,
                    userType: req.session.user.userType
                });
            }
            
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Enhanced authorization middleware for managers only with fail-secure logging
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isManager(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.MANAGER, req.session.user)) {
            // Log failed access attempt
            if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                logSecurityEvent('warn', 'Manager-only access denied', {
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    requestedUrl: req.originalUrl,
                    method: req.method,
                    sessionId: req.sessionID,
                    userId: req.session.user._id,
                    userType: req.session.user.userType
                });
            }
            
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Enhanced authorization middleware for administrators only with fail-secure logging
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isAdministrator(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.ADMINISTRATOR, req.session.user)) {
            // Log failed access attempt
            if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                logSecurityEvent('warn', 'Administrator-only access denied', {
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    requestedUrl: req.originalUrl,
                    method: req.method,
                    sessionId: req.sessionID,
                    userId: req.session.user._id,
                    userType: req.session.user.userType
                });
            }
            
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.ADMIN);
        }
        
        next();
    });
}

/**
 * Enhanced authorization middleware for users with at least the specified role level
 * @param {string} minimumRole - Minimum required role level
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function hasMinimumRole(minimumRole) {
    return (req, res, next) => {
        validateSession(req, res, (err) => {
            if (err) return next(err);
            
            if (!hasRoleLevel(minimumRole, req.session.user)) {
                // Log failed access attempt
                if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                    logSecurityEvent('warn', `Minimum role access denied (required: ${minimumRole})`, {
                        ipAddress: req.ip,
                        userAgent: req.get('User-Agent'),
                        requestedUrl: req.originalUrl,
                        method: req.method,
                        sessionId: req.sessionID,
                        userId: req.session.user._id,
                        userType: req.session.user.userType,
                        requiredRole: minimumRole
                    });
                }
                
                return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
            }
            
            next();
        });
    };
}

/**
 * Enhanced authorization middleware for resource ownership with fail-secure logging
 * @param {Function} resourceOwnerCheck - Function that returns true if user owns the resource
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isResourceOwner(resourceOwnerCheck) {
    return (req, res, next) => {
        validateSession(req, res, (err) => {
            if (err) return next(err);
            
            // Validate the resourceOwnerCheck function
            if (typeof resourceOwnerCheck !== 'function') {
                console.error('isResourceOwner: resourceOwnerCheck must be a function');
                return res.status(500).render('error', {
                    error: 'Server Error',
                    message: 'Authorization system error.',
                    layout: false
                });
            }
            
            try {
                if (!resourceOwnerCheck(req)) {
                    // Log failed access attempt
                    if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                        logSecurityEvent('warn', 'Resource ownership access denied', {
                            ipAddress: req.ip,
                            userAgent: req.get('User-Agent'),
                            requestedUrl: req.originalUrl,
                            method: req.method,
                            sessionId: req.sessionID,
                            userId: req.session.user._id,
                            userType: req.session.user.userType,
                            resourceId: req.params.id || req.body.id || 'Unknown'
                        });
                    }
                    
                    return res.status(403).render('error', {
                        error: 'Access Denied',
                        message: AUTH_CONFIG.FAIL_SECURE.ERROR_MESSAGES.ACCESS_DENIED,
                        layout: false
                    });
                }
                
                next();
            } catch (error) {
                // Log the error and fail securely
                if (AUTH_CONFIG.FAIL_SECURE.LOG_SUSPICIOUS_ACTIVITY) {
                    logSecurityEvent('error', 'Resource ownership check failed with error', {
                        ipAddress: req.ip,
                        userAgent: req.get('User-Agent'),
                        requestedUrl: req.originalUrl,
                        method: req.method,
                        sessionId: req.sessionID,
                        userId: req.session.user._id,
                        userType: req.session.user.userType,
                        error: error.message
                    });
                }
                
                return res.status(500).render('error', {
                    error: 'Server Error',
                    message: 'Authorization check failed.',
                    layout: false
                });
            }
        });
    };
}

/**
 * Enhanced authorization middleware for specific user types with fail-secure logging
 * @param {Array<string>} allowedUserTypes - Array of allowed user types
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function allowUserTypes(allowedUserTypes) {
    return (req, res, next) => {
        validateSession(req, res, (err) => {
            if (err) return next(err);
            
            // Validate that allowedUserTypes is an array
            if (!Array.isArray(allowedUserTypes)) {
                console.error('allowUserTypes: allowedUserTypes must be an array');
                return res.status(500).render('error', {
                    error: 'Server Error',
                    message: 'Authorization system error.',
                    layout: false
                });
            }
            
            if (!hasAnyRole(allowedUserTypes, req.session.user)) {
                // Log failed access attempt
                if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                    logSecurityEvent('warn', 'User type access denied', {
                        ipAddress: req.ip,
                        userAgent: req.get('User-Agent'),
                        requestedUrl: req.originalUrl,
                        method: req.method,
                        sessionId: req.sessionID,
                        userId: req.session.user._id,
                        userType: req.session.user.userType,
                        allowedUserTypes
                    });
                }
                
                return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
            }
            
            next();
        });
    };
}

/**
 * Enhanced utility function to check if user can perform an action with fail-secure validation
 * @param {Object} user - User object from session
 * @param {string} action - Action to check
 * @param {Object} context - Additional context for the action
 * @returns {boolean} - True if user can perform the action
 */
function canPerformAction(user, action, context = {}) {
    // Fail securely - deny access if user data is invalid
    if (!user || !user.userType) {
        return false;
    }
    
    // Validate that action is a string
    if (typeof action !== 'string') {
        console.error('canPerformAction: action must be a string');
        return false;
    }
    
    // Define action permissions based on user type
    const actionPermissions = {
        'create_review': [AUTH_CONFIG.USER_TYPES.STUDENT],
        'edit_review': [AUTH_CONFIG.USER_TYPES.STUDENT, AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'delete_review': [AUTH_CONFIG.USER_TYPES.STUDENT, AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'moderate_reviews': [AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'manage_users': [AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'view_admin_panel': [AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'view_moderator_panel': [AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'delete_user': [AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'update_user_role': [AUTH_CONFIG.USER_TYPES.ADMINISTRATOR],
        'view_user_data': [AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR]
    };
    
    const allowedRoles = actionPermissions[action];
    if (!allowedRoles) {
        // Log unknown action for security monitoring
        if (AUTH_CONFIG.FAIL_SECURE.LOG_SUSPICIOUS_ACTIVITY) {
            logSecurityEvent('warn', 'Unknown action requested', {
                action,
                userType: user.userType,
                userId: user._id,
                context
            });
        }
        return false;
    }
    
    return hasAnyRole(allowedRoles, user);
}

/**
 * Enhanced middleware for action-based authorization with fail-secure logging
 * @param {string} action - Action to authorize
 * @param {Function} contextProvider - Function to provide context for the action
 * @returns {Function} - Express middleware function
 */
function canPerformActionMiddleware(action, contextProvider = null) {
    return (req, res, next) => {
        validateSession(req, res, (err) => {
            if (err) return next(err);
            
            const context = contextProvider ? contextProvider(req) : {};
            
            if (!canPerformAction(req.session.user, action, context)) {
                // Log failed access attempt
                if (AUTH_CONFIG.FAIL_SECURE.LOG_FAILED_ATTEMPTS) {
                    logSecurityEvent('warn', `Action access denied: ${action}`, {
                        ipAddress: req.ip,
                        userAgent: req.get('User-Agent'),
                        requestedUrl: req.originalUrl,
                        method: req.method,
                        sessionId: req.sessionID,
                        userId: req.session.user._id,
                        userType: req.session.user.userType,
                        action,
                        context
                    });
                }
                
                return res.status(403).render('error', {
                    error: 'Access Denied',
                    message: AUTH_CONFIG.FAIL_SECURE.ERROR_MESSAGES.INSUFFICIENT_PRIVILEGES,
                    layout: false
                });
            }
            
            next();
        });
    };
}

/**
 * Export all authorization functions and configuration
 */
module.exports = {
    // Configuration
    AUTH_CONFIG,
    
    // Core authorization middleware
    isLoggedIn,
    isStudent,
    isProfessor,
    isModerator,
    isManager,
    isAdministrator,
    
    // Dynamic authorization middleware
    hasMinimumRole,
    isResourceOwner,
    allowUserTypes,
    canPerformActionMiddleware,
    
    // Utility functions
    hasRoleLevel,
    hasExactRole,
    hasAnyRole,
    canPerformAction,
    validateSession,
    
    // Security logging
    logSecurityEvent
};
