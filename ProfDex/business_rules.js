/**
 * Business Rules Enforcement System for ProfDex
 *
 * This file implements requirement 2.2.3: Enforce application logic flows to comply with business rules
 */

const { User, Student, Professor, Manager, Administrator, Post, Comment, Course, Subject } = require('./db/controller');

/**
 * Business Rules Configuration
 */
const BUSINESS_RULES_CONFIG = {
    // Review creation rules
    REVIEW: {
        MIN_TEXT_LENGTH: 10,
        MAX_TEXT_LENGTH: 2000,
        RATING_MIN: 1,
        RATING_MAX: 5,
        ONE_REVIEW_PER_PROFESSOR: true,
        STUDENTS_ONLY: true,
        NO_SELF_REVIEW: true
    },

    // User registration and profile rules
    USER: {
        MIN_NAME_LENGTH: 2,
        MAX_NAME_LENGTH: 50,
        MIN_BIO_LENGTH: 0,
        MAX_BIO_LENGTH: 500,
        REQUIRED_FIELDS: {
            STUDENT: ['studentID', 'course'],
            PROFESSOR: ['teacherID'],
            MANAGER: [],
            ADMINISTRATOR: []
        }
    },

    // Error messages
    ERROR_MESSAGES: {
        INVALID_USER_TYPE: 'Invalid user type for this operation.',
        INSUFFICIENT_PERMISSIONS: 'You do not have permission to perform this action.',
        BUSINESS_RULE_VIOLATION: 'This operation violates business rules.',
        DATA_INTEGRITY_ERROR: 'Data integrity check failed.',
        INVALID_STATE: 'Operation cannot be performed in current state.',
        DUPLICATE_OPERATION: 'This operation has already been performed.',
        RESOURCE_NOT_FOUND: 'Required resource not found.',
        INVALID_INPUT: 'Invalid input provided.'
    }
};

/**
 * Business rule validation logging
 */
function logBusinessRuleEvent(level, message, context = {}) {
    const timestamp = new Date().toISOString();
    console.log(`[BUSINESS ${level.toUpperCase()}] ${timestamp}: ${message}`, context);
}

/**
 * Validate user type consistency and business rules
 */
async function validateUserBusinessRules(user, operation, context = {}) {
    try {
        if (!user || !user._id || !user.userType || !user.email) {
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_USER_TYPE,
                details: 'User data is incomplete or invalid'
            };
        }

        const allowedUserTypes = ['student', 'professor', 'manager', 'administrator'];
        if (!allowedUserTypes.includes(user.userType)) {
            logBusinessRuleEvent('error', 'Invalid user type detected', {
                userId: user._id,
                userType: user.userType,
                operation
            });
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_USER_TYPE,
                details: `User type '${user.userType}' is not valid`
            };
        }

        const operationValidation = await validateOperationBusinessRules(user, operation, context);
        if (!operationValidation.isValid) {
            return operationValidation;
        }

        return { isValid: true };
    } catch (error) {
        logBusinessRuleEvent('error', 'Error validating user business rules', {
            userId: user?._id,
            operation,
            error: error.message
        });
        return {
            isValid: false,
            error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
            details: 'Business rule validation failed'
        };
    }
}

/**
 * Validate operation-specific business rules
 */
async function validateOperationBusinessRules(user, operation, context = {}) {
    try {
        switch (operation) {
            case 'create_review':
                return await validateReviewCreationRules(user, context);
            case 'edit_review':
                return await validateReviewEditRules(user, context);
            case 'delete_review':
                return await validateReviewDeletionRules(user, context);
            case 'edit_profile':
                return await validateProfileEditRules(user, context);
            default:
                return { isValid: true };
        }
    } catch (error) {
        logBusinessRuleEvent('error', 'Error validating operation business rules', {
            userId: user._id,
            operation,
            error: error.message
        });
        return {
            isValid: false,
            error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
            details: 'Operation validation failed'
        };
    }
}

/**
 * Validate review creation business rules
 */
async function validateReviewCreationRules(user, context) {
    try {
        if (BUSINESS_RULES_CONFIG.REVIEW.STUDENTS_ONLY && user.userType !== 'student') {
            logBusinessRuleEvent('warn', 'Non-student attempted to create review', {
                userId: user._id,
                userType: user.userType
            });
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INSUFFICIENT_PERMISSIONS,
                details: 'Only students can create reviews'
            };
        }

        if (BUSINESS_RULES_CONFIG.REVIEW.NO_SELF_REVIEW && 
            user.userType === 'professor' && 
            context.professorId === user._id) {
            logBusinessRuleEvent('warn', 'Professor attempted to review themselves', {
                userId: user._id
            });
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
                details: 'Professors cannot review themselves'
            };
        }

        if (BUSINESS_RULES_CONFIG.REVIEW.ONE_REVIEW_PER_PROFESSOR && context.professorId) {
            const existingReview = await Post.findOne({
                op: user._id,
                to: context.professorId
            });

            if (existingReview) {
                logBusinessRuleEvent('warn', 'User attempted to create duplicate review', {
                    userId: user._id,
                    professorId: context.professorId
                });
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.DUPLICATE_OPERATION,
                    details: 'You already have a review for this professor'
                };
            }
        }

        if (context.text) {
            if (context.text.length < BUSINESS_RULES_CONFIG.REVIEW.MIN_TEXT_LENGTH) {
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_INPUT,
                    details: `Review text must be at least ${BUSINESS_RULES_CONFIG.REVIEW.MIN_TEXT_LENGTH} characters`
                };
            }

            if (context.text.length > BUSINESS_RULES_CONFIG.REVIEW.MAX_TEXT_LENGTH) {
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_INPUT,
                    details: `Review text must be no more than ${BUSINESS_RULES_CONFIG.REVIEW.MAX_TEXT_LENGTH} characters`
                };
            }
        }

        return { isValid: true };
    } catch (error) {
        logBusinessRuleEvent('error', 'Error validating review creation rules', {
            userId: user._id,
            error: error.message
        });
        return {
            isValid: false,
            error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
            details: 'Review creation validation failed'
        };
    }
}

/**
 * Validate review edit business rules
 */
async function validateReviewEditRules(user, context) {
    try {
        if (!context.reviewId) {
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.RESOURCE_NOT_FOUND,
                details: 'Review ID is required'
            };
        }

        const review = await Post.findById(context.reviewId);
        if (!review) {
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.RESOURCE_NOT_FOUND,
                details: 'Review not found'
            };
        }

        const isOwner = review.op === user._id;
        const isModerator = ['manager', 'administrator'].includes(user.userType);

        if (!isOwner && !isModerator) {
            logBusinessRuleEvent('warn', 'Unauthorized review edit attempt', {
                userId: user._id,
                reviewId: context.reviewId,
                reviewOwner: review.op
            });
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INSUFFICIENT_PERMISSIONS,
                details: 'You can only edit your own reviews'
            };
        }

        return { isValid: true };
    } catch (error) {
        logBusinessRuleEvent('error', 'Error validating review edit rules', {
            userId: user._id,
            error: error.message
        });
        return {
            isValid: false,
            error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
            details: 'Review edit validation failed'
        };
    }
}

/**
 * Validate review deletion business rules
 */
async function validateReviewDeletionRules(user, context) {
    try {
        if (!context.reviewId) {
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.RESOURCE_NOT_FOUND,
                details: 'Review ID is required'
            };
        }

        const review = await Post.findById(context.reviewId);
        if (!review) {
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.RESOURCE_NOT_FOUND,
                details: 'Review not found'
            };
        }

        const isOwner = review.op === user._id;
        const isModerator = ['manager', 'administrator'].includes(user.userType);

        if (!isOwner && !isModerator) {
            logBusinessRuleEvent('warn', 'Unauthorized review deletion attempt', {
                userId: user._id,
                reviewId: context.reviewId,
                reviewOwner: review.op
            });
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INSUFFICIENT_PERMISSIONS,
                details: 'You can only delete your own reviews'
            };
        }

        return { isValid: true };
    } catch (error) {
        logBusinessRuleEvent('error', 'Error validating review deletion rules', {
            userId: user._id,
            error: error.message
        });
        return {
            isValid: false,
            error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
            details: 'Review deletion validation failed'
        };
    }
}

/**
 * Validate profile edit business rules
 */
async function validateProfileEditRules(user, context) {
    try {
        if (context.firstName) {
            if (context.firstName.length < BUSINESS_RULES_CONFIG.USER.MIN_NAME_LENGTH ||
                context.firstName.length > BUSINESS_RULES_CONFIG.USER.MAX_NAME_LENGTH) {
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_INPUT,
                    details: `First name must be between ${BUSINESS_RULES_CONFIG.USER.MIN_NAME_LENGTH} and ${BUSINESS_RULES_CONFIG.USER.MAX_NAME_LENGTH} characters`
                };
            }
        }

        if (context.lastName) {
            if (context.lastName.length < BUSINESS_RULES_CONFIG.USER.MIN_NAME_LENGTH ||
                context.lastName.length > BUSINESS_RULES_CONFIG.USER.MAX_NAME_LENGTH) {
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_INPUT,
                    details: `Last name must be between ${BUSINESS_RULES_CONFIG.USER.MIN_NAME_LENGTH} and ${BUSINESS_RULES_CONFIG.USER.MAX_NAME_LENGTH} characters`
                };
            }
        }

        if (context.bio && context.bio.length > BUSINESS_RULES_CONFIG.USER.MAX_BIO_LENGTH) {
            return {
                isValid: false,
                error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_INPUT,
                details: `Bio must be no more than ${BUSINESS_RULES_CONFIG.USER.MAX_BIO_LENGTH} characters`
            };
        }

        if (context.email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(context.email)) {
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.INVALID_INPUT,
                    details: 'Invalid email format'
                };
            }

            const existingUser = await User.findOne({ 
                email: context.email.toLowerCase(),
                _id: { $ne: user._id }
            });
            if (existingUser) {
                return {
                    isValid: false,
                    error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.DUPLICATE_OPERATION,
                    details: 'Email is already taken by another user'
                };
            }
        }

        return { isValid: true };
    } catch (error) {
        logBusinessRuleEvent('error', 'Error validating profile edit rules', {
            userId: user._id,
            error: error.message
        });
        return {
            isValid: false,
            error: BUSINESS_RULES_CONFIG.ERROR_MESSAGES.BUSINESS_RULE_VIOLATION,
            details: 'Profile edit validation failed'
        };
    }
}

/**
 * Middleware for enforcing business rules
 */
function enforceBusinessRulesMiddleware(operation, contextProvider = null) {
    return async (req, res, next) => {
        try {
            const user = req.session.user;
            if (!user) {
                return res.status(401).render('error', {
                    error: 'Unauthorized',
                    message: 'You must be logged in to perform this action.',
                    layout: false
                });
            }

            const context = contextProvider ? contextProvider(req) : {};
            const validation = await validateUserBusinessRules(user, operation, context);
            
            if (!validation.isValid) {
                logBusinessRuleEvent('warn', 'Business rule violation detected', {
                    userId: user._id,
                    operation,
                    error: validation.error,
                    details: validation.details
                });

                return res.status(400).render('error', {
                    error: 'Business Rule Violation',
                    message: validation.error,
                    details: validation.details,
                    layout: false
                });
            }

            next();
        } catch (error) {
            logBusinessRuleEvent('error', 'Error in business rules middleware', {
                operation,
                error: error.message
            });

            return res.status(500).render('error', {
                error: 'Server Error',
                message: 'Business rule validation failed.',
                layout: false
            });
        }
    };
}

module.exports = {
    BUSINESS_RULES_CONFIG,
    validateUserBusinessRules,
    validateOperationBusinessRules,
    validateReviewCreationRules,
    validateReviewEditRules,
    validateReviewDeletionRules,
    validateProfileEditRules,
    enforceBusinessRulesMiddleware,
    logBusinessRuleEvent
};
