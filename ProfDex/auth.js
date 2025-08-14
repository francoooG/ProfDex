/**
 * Centralized Authorization System for ProfDex
 * 
 * This file implements requirement 2.2.1: Use a single site-wide component to check access authorization
 * 
 * All authorization logic is centralized here to ensure consistency, maintainability,
 * and security across the entire application.
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
    }
};

/**
 * Base authorization middleware that validates session integrity
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object  
 * @param {Function} next - Express next function
 * @returns {void}
 */
function validateSession(req, res, next) {
    // Fail securely - deny access by default
    if (!req.session || !req.session.user) {
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
        console.log(`Invalid session data detected, missing fields: ${missingFields.join(', ')}`);
        req.session.destroy();
        return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
    }
    
    next();
}

/**
 * Check if user has at least the specified role level
 * @param {string} requiredRole - Minimum required role
 * @param {Object} user - User object from session
 * @returns {boolean} - True if user has sufficient privileges
 */
function hasRoleLevel(requiredRole, user) {
    if (!user || !user.userType) {
        return false;
    }
    
    const userLevel = AUTH_CONFIG.ROLE_HIERARCHY[user.userType] || 0;
    const requiredLevel = AUTH_CONFIG.ROLE_HIERARCHY[requiredRole] || 0;
    
    return userLevel >= requiredLevel;
}

/**
 * Check if user has exactly the specified role
 * @param {string} exactRole - Exact role required
 * @param {Object} user - User object from session
 * @returns {boolean} - True if user has exact role
 */
function hasExactRole(exactRole, user) {
    if (!user || !user.userType) {
        return false;
    }
    
    return user.userType === exactRole;
}

/**
 * Check if user has any of the specified roles
 * @param {Array<string>} allowedRoles - Array of allowed roles
 * @param {Object} user - User object from session
 * @returns {boolean} - True if user has any of the allowed roles
 */
function hasAnyRole(allowedRoles, user) {
    if (!user || !user.userType) {
        return false;
    }
    
    return allowedRoles.includes(user.userType);
}

/**
 * Authorization middleware for basic authentication (any logged-in user)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isLoggedIn(req, res, next) {
    validateSession(req, res, next);
}

/**
 * Authorization middleware for students only
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isStudent(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.STUDENT, req.session.user)) {
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Authorization middleware for professors only
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isProfessor(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.PROFESSOR, req.session.user)) {
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Authorization middleware for moderators (managers and administrators)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isModerator(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasAnyRole([AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR], req.session.user)) {
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Authorization middleware for managers only
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isManager(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.MANAGER, req.session.user)) {
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
        }
        
        next();
    });
}

/**
 * Authorization middleware for administrators only
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 * @returns {void}
 */
function isAdministrator(req, res, next) {
    validateSession(req, res, (err) => {
        if (err) return next(err);
        
        if (!hasExactRole(AUTH_CONFIG.USER_TYPES.ADMINISTRATOR, req.session.user)) {
            return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.ADMIN);
        }
        
        next();
    });
}

/**
 * Authorization middleware for users with at least the specified role level
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
                return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
            }
            
            next();
        });
    };
}

/**
 * Authorization middleware for resource ownership (users can only access their own resources)
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
            
            if (!resourceOwnerCheck(req)) {
                return res.status(403).render('error', {
                    error: 'Access Denied',
                    message: 'You do not have permission to access this resource.',
                    layout: false
                });
            }
            
            next();
        });
    };
}

/**
 * Authorization middleware for specific user types
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
            
            if (!hasAnyRole(allowedUserTypes, req.session.user)) {
                return res.redirect(AUTH_CONFIG.SESSION_VALIDATION.REDIRECT_URLS.DEFAULT);
            }
            
            next();
        });
    };
}

/**
 * Utility function to check if user can perform an action
 * @param {Object} user - User object from session
 * @param {string} action - Action to check
 * @param {Object} context - Additional context for the action
 * @returns {boolean} - True if user can perform the action
 */
function canPerformAction(user, action, context = {}) {
    if (!user || !user.userType) {
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
        'view_moderator_panel': [AUTH_CONFIG.USER_TYPES.MANAGER, AUTH_CONFIG.USER_TYPES.ADMINISTRATOR]
    };
    
    const allowedRoles = actionPermissions[action];
    if (!allowedRoles) {
        return false;
    }
    
    return hasAnyRole(allowedRoles, user);
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
    
    // Utility functions
    hasRoleLevel,
    hasExactRole,
    hasAnyRole,
    canPerformAction,
    validateSession
};
