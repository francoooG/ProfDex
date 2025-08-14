

// Data validation configuration
const VALIDATION_CONFIG = {
    // User data validation rules
    USER: {
        FIRST_NAME: {
            MIN_LENGTH: 2,
            MAX_LENGTH: 50,
            PATTERN: /^[a-zA-Z\s\-']+$/,
            ALLOWED_CHARS: 'Letters, spaces, hyphens, and apostrophes only'
        },
        LAST_NAME: {
            MIN_LENGTH: 2,
            MAX_LENGTH: 50,
            PATTERN: /^[a-zA-Z\s\-']+$/,
            ALLOWED_CHARS: 'Letters, spaces, hyphens, and apostrophes only'
        },
        EMAIL: {
            MIN_LENGTH: 5,
            MAX_LENGTH: 254,
            PATTERN: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
            ALLOWED_CHARS: 'Valid email format required'
        },
        BIO: {
            MIN_LENGTH: 0,
            MAX_LENGTH: 500,
            PATTERN: /^[a-zA-Z0-9\s\-_.,!?()'"]*$/,
            ALLOWED_CHARS: 'Letters, numbers, spaces, and basic punctuation only'
        },
        STUDENT_ID: {
            MIN_LENGTH: 5,
            MAX_LENGTH: 20,
            PATTERN: /^[A-Z0-9\-]+$/,
            ALLOWED_CHARS: 'Uppercase letters, numbers, and hyphens only'
        },
        TEACHER_ID: {
            MIN_LENGTH: 5,
            MAX_LENGTH: 20,
            PATTERN: /^[A-Z0-9\-]+$/,
            ALLOWED_CHARS: 'Uppercase letters, numbers, and hyphens only'
        }
    },

    // Review data validation rules
    REVIEW: {
        TEXT: {
            MIN_LENGTH: 10,
            MAX_LENGTH: 2000,
            PATTERN: /^[a-zA-Z0-9\s\-_.,!?()'":;@#$%^&*+=<>[\]{}|\\/~`]*$/,
            ALLOWED_CHARS: 'Letters, numbers, spaces, and common punctuation only'
        },
        RATINGS: {
            MIN_VALUE: 1,
            MAX_VALUE: 5,
            ALLOWED_VALUES: [1, 2, 3, 4, 5]
        }
    },

    // Course and Subject validation rules
    COURSE: {
        NAME: {
            MIN_LENGTH: 3,
            MAX_LENGTH: 100,
            PATTERN: /^[a-zA-Z0-9\s\-_()&]+$/,
            ALLOWED_CHARS: 'Letters, numbers, spaces, hyphens, underscores, parentheses, and ampersands only'
        },
        CODE: {
            MIN_LENGTH: 2,
            MAX_LENGTH: 20,
            PATTERN: /^[A-Z0-9\-]+$/,
            ALLOWED_CHARS: 'Uppercase letters, numbers, and hyphens only'
        }
    },

    // Search validation rules
    SEARCH: {
        QUERY: {
            MIN_LENGTH: 1,
            MAX_LENGTH: 100,
            PATTERN: /^[a-zA-Z0-9\s\-_.,]+$/,
            ALLOWED_CHARS: 'Letters, numbers, spaces, hyphens, underscores, dots, and commas only'
        }
    },

    // Comment validation rules
    COMMENT: {
        TEXT: {
            MIN_LENGTH: 1,
            MAX_LENGTH: 500,
            PATTERN: /^[a-zA-Z0-9\s\-_.,!?()'":;@#$%^&*+=<>[\]{}|\\/~`]*$/,
            ALLOWED_CHARS: 'Letters, numbers, spaces, and common punctuation only'
        }
    },

    // Security answer validation rules
    SECURITY_ANSWER: {
        MIN_LENGTH: 3,
        MAX_LENGTH: 100,
        PATTERN: /^[a-zA-Z0-9\s\-_.,!?()'"]*$/,
        ALLOWED_CHARS: 'Letters, numbers, spaces, and basic punctuation only'
    },

    // General validation settings
    GENERAL: {
        REJECT_ON_FIRST_ERROR: true, // Stop validation on first error (fail-fast)
        LOG_VALIDATION_FAILURES: true, // Log all validation failures for security monitoring
        MAX_VALIDATION_ERRORS: 10, // Maximum number of errors to collect before stopping
        ENABLE_STRICT_MODE: true // Enable strict validation mode
    }
};

/**
 * Validation result object structure
 */
class ValidationResult {
    constructor() {
        this.isValid = true;
        this.errors = [];
        this.warnings = [];
        this.rejectedFields = [];
        this.validationDetails = {};
    }

    addError(field, message, details = {}) {
        this.isValid = false;
        this.errors.push({
            field,
            message,
            details,
            timestamp: new Date().toISOString()
        });
        this.rejectedFields.push(field);
        
        if (VALIDATION_CONFIG.GENERAL.LOG_VALIDATION_FAILURES) {
            console.log(`VALIDATION ERROR [${field}]: ${message}`, details);
        }
    }

    addWarning(field, message, details = {}) {
        this.warnings.push({
            field,
            message,
            details,
            timestamp: new Date().toISOString()
        });
    }

    addValidationDetail(field, detail) {
        this.validationDetails[field] = detail;
    }

    hasErrors() {
        return this.errors.length > 0;
    }

    getFirstError() {
        return this.errors.length > 0 ? this.errors[0] : null;
    }

    getAllErrors() {
        return this.errors;
    }

    getRejectedFields() {
        return [...new Set(this.rejectedFields)];
    }
}

/**
 * Centralized validation logging for security monitoring
 */
function logValidationEvent(level, message, details = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        details,
        component: 'data_validation'
    };

    console.log(`[VALIDATION ${level.toUpperCase()}] ${message}`, details);
    
    // 2.4.5: Log all input validation failures
    if (level === 'error' || level === 'security') {
        // Import the logging function dynamically to avoid circular dependencies
        const { logValidationFailure } = require('./error_handling');
        logValidationFailure({
            message,
            details,
            level,
            timestamp: new Date(),
            component: 'data_validation'
        }).catch(err => {
            console.error('Failed to log validation event:', err);
        });
    }
}

/**
 * 2.3.1: Input rejection without sanitizing
 * Validates input and rejects invalid data without attempting to sanitize
 */
function validateInput(input, fieldName, validationRules) {
    const result = new ValidationResult();
    
    // Check if input exists
    if (input === null || input === undefined) {
        result.addError(fieldName, `Field '${fieldName}' is required`, {
            type: 'missing_field',
            expected: 'non-null value'
        });
        return result;
    }

    // Convert to string for validation if not already
    const stringInput = String(input).trim();
    
    // 2.3.3: Validate data length
    if (validationRules.MIN_LENGTH !== undefined && stringInput.length < validationRules.MIN_LENGTH) {
        result.addError(fieldName, `Field '${fieldName}' must be at least ${validationRules.MIN_LENGTH} characters long`, {
            type: 'length_validation',
            current: stringInput.length,
            minimum: validationRules.MIN_LENGTH,
            actual: stringInput
        });
    }
    
    if (validationRules.MAX_LENGTH !== undefined && stringInput.length > validationRules.MAX_LENGTH) {
        result.addError(fieldName, `Field '${fieldName}' must be no more than ${validationRules.MAX_LENGTH} characters long`, {
            type: 'length_validation',
            current: stringInput.length,
            maximum: validationRules.MAX_LENGTH,
            actual: stringInput
        });
    }

    // Pattern validation (character set validation)
    if (validationRules.PATTERN && !validationRules.PATTERN.test(stringInput)) {
        result.addError(fieldName, `Field '${fieldName}' contains invalid characters. ${validationRules.ALLOWED_CHARS}`, {
            type: 'pattern_validation',
            pattern: validationRules.PATTERN.toString(),
            allowed_chars: validationRules.ALLOWED_CHARS,
            actual: stringInput
        });
    }

    // 2.3.2: Validate data range (for numeric fields)
    if (validationRules.MIN_VALUE !== undefined || validationRules.MAX_VALUE !== undefined) {
        const numericValue = Number(stringInput);
        
        if (isNaN(numericValue)) {
            result.addError(fieldName, `Field '${fieldName}' must be a valid number`, {
                type: 'range_validation',
                expected: 'numeric value',
                actual: stringInput
            });
        } else {
            if (validationRules.MIN_VALUE !== undefined && numericValue < validationRules.MIN_VALUE) {
                result.addError(fieldName, `Field '${fieldName}' must be at least ${validationRules.MIN_VALUE}`, {
                    type: 'range_validation',
                    current: numericValue,
                    minimum: validationRules.MIN_VALUE,
                    actual: stringInput
                });
            }
            
            if (validationRules.MAX_VALUE !== undefined && numericValue > validationRules.MAX_VALUE) {
                result.addError(fieldName, `Field '${fieldName}' must be no more than ${validationRules.MAX_VALUE}`, {
                    type: 'range_validation',
                    current: numericValue,
                    maximum: validationRules.MAX_VALUE,
                    actual: stringInput
                });
            }
            
            // Check for allowed values if specified
            if (validationRules.ALLOWED_VALUES && !validationRules.ALLOWED_VALUES.includes(numericValue)) {
                result.addError(fieldName, `Field '${fieldName}' must be one of: ${validationRules.ALLOWED_VALUES.join(', ')}`, {
                    type: 'range_validation',
                    allowed_values: validationRules.ALLOWED_VALUES,
                    actual: numericValue
                });
            }
        }
    }

    // Security validation: Check for potentially dangerous patterns
    if (VALIDATION_CONFIG.GENERAL.ENABLE_STRICT_MODE) {
        // Check for SQL injection patterns
        const sqlPatterns = [
            /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute|script)\b)/i,
            /(['"]\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)\s*['"])/i,
            /(\b(and|or)\s+\d+\s*=\s*\d+)/i,
            /(\b(and|or)\s+['"]\w+['"]\s*=\s*['"]\w+['"])/i
        ];
        
        for (const pattern of sqlPatterns) {
            if (pattern.test(stringInput)) {
                result.addError(fieldName, `Field '${fieldName}' contains potentially dangerous content`, {
                    type: 'security_validation',
                    pattern: pattern.toString(),
                    actual: stringInput,
                    severity: 'high'
                });
                logValidationEvent('security', `Potential SQL injection attempt in field '${fieldName}'`, {
                    pattern: pattern.toString(),
                    input: stringInput
                });
                break;
            }
        }

        // Check for XSS patterns
        const xssPatterns = [
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
            /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
            /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi
        ];
        
        for (const pattern of xssPatterns) {
            if (pattern.test(stringInput)) {
                result.addError(fieldName, `Field '${fieldName}' contains potentially dangerous content`, {
                    type: 'security_validation',
                    pattern: pattern.toString(),
                    actual: stringInput,
                    severity: 'high'
                });
                logValidationEvent('security', `Potential XSS attempt in field '${fieldName}'`, {
                    pattern: pattern.toString(),
                    input: stringInput
                });
                break;
            }
        }
    }

    return result;
}

/**
 * Validate user registration data
 */
function validateUserRegistration(data) {
    const result = new ValidationResult();
    
    // Validate first name
    const firstNameValidation = validateInput(data.firstName, 'firstName', VALIDATION_CONFIG.USER.FIRST_NAME);
    if (firstNameValidation.hasErrors()) {
        result.errors.push(...firstNameValidation.errors);
    }
    
    // Validate last name
    const lastNameValidation = validateInput(data.lastName, 'lastName', VALIDATION_CONFIG.USER.LAST_NAME);
    if (lastNameValidation.hasErrors()) {
        result.errors.push(...lastNameValidation.errors);
    }
    
    // Validate email
    const emailValidation = validateInput(data.email, 'email', VALIDATION_CONFIG.USER.EMAIL);
    if (emailValidation.hasErrors()) {
        result.errors.push(...emailValidation.errors);
    }
    
    // Validate user type
    const validUserTypes = ['student', 'professor', 'manager'];
    if (!data.userType || !validUserTypes.includes(data.userType)) {
        result.addError('userType', `User type must be one of: ${validUserTypes.join(', ')}`, {
            type: 'enum_validation',
            allowed_values: validUserTypes,
            actual: data.userType
        });
    }
    
    // Validate student-specific fields
    if (data.userType === 'student') {
        if (data.studentID) {
            const studentIdValidation = validateInput(data.studentID, 'studentID', VALIDATION_CONFIG.USER.STUDENT_ID);
            if (studentIdValidation.hasErrors()) {
                result.errors.push(...studentIdValidation.errors);
            }
        }
    }
    
    // Validate professor-specific fields
    if (data.userType === 'professor') {
        if (data.teacherID) {
            const teacherIdValidation = validateInput(data.teacherID, 'teacherID', VALIDATION_CONFIG.USER.TEACHER_ID);
            if (teacherIdValidation.hasErrors()) {
                result.errors.push(...teacherIdValidation.errors);
            }
        }
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Validate review creation data
 */
function validateReviewCreation(data) {
    const result = new ValidationResult();
    
    // Validate professor ID
    if (!data.professorId || typeof data.professorId !== 'string') {
        result.addError('professorId', 'Professor ID is required and must be a valid string', {
            type: 'required_field',
            expected: 'non-empty string',
            actual: data.professorId
        });
    }
    
    // Validate review text
    const textValidation = validateInput(data.text, 'text', VALIDATION_CONFIG.REVIEW.TEXT);
    if (textValidation.hasErrors()) {
        result.errors.push(...textValidation.errors);
    }
    
    // Validate ratings
    const ratingFields = ['generosity', 'difficulty', 'engagement', 'proficiency', 'workload'];
    for (const field of ratingFields) {
        if (data.ratings && data.ratings[field] !== undefined) {
            const ratingValidation = validateInput(data.ratings[field], field, VALIDATION_CONFIG.REVIEW.RATINGS);
            if (ratingValidation.hasErrors()) {
                result.errors.push(...ratingValidation.errors);
            }
        } else {
            result.addError(field, `Rating '${field}' is required`, {
                type: 'required_field',
                expected: 'numeric rating between 1-5',
                actual: data.ratings ? data.ratings[field] : 'undefined'
            });
        }
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Validate profile edit data
 */
function validateProfileEdit(data) {
    const result = new ValidationResult();
    
    // Validate first name
    if (data.firstName) {
        const firstNameValidation = validateInput(data.firstName, 'firstName', VALIDATION_CONFIG.USER.FIRST_NAME);
        if (firstNameValidation.hasErrors()) {
            result.errors.push(...firstNameValidation.errors);
        }
    }
    
    // Validate last name
    if (data.lastName) {
        const lastNameValidation = validateInput(data.lastName, 'lastName', VALIDATION_CONFIG.USER.LAST_NAME);
        if (lastNameValidation.hasErrors()) {
            result.errors.push(...lastNameValidation.errors);
        }
    }
    
    // Validate bio (optional)
    if (data.bio) {
        const bioValidation = validateInput(data.bio, 'bio', VALIDATION_CONFIG.USER.BIO);
        if (bioValidation.hasErrors()) {
            result.errors.push(...bioValidation.errors);
        }
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Validate search query
 */
function validateSearchQuery(query) {
    const result = new ValidationResult();
    
    const searchValidation = validateInput(query, 'search', VALIDATION_CONFIG.SEARCH.QUERY);
    if (searchValidation.hasErrors()) {
        result.errors.push(...searchValidation.errors);
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Validate comment data
 */
function validateComment(data) {
    const result = new ValidationResult();
    
    const textValidation = validateInput(data.text, 'text', VALIDATION_CONFIG.COMMENT.TEXT);
    if (textValidation.hasErrors()) {
        result.errors.push(...textValidation.errors);
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Validate security answer
 */
function validateSecurityAnswer(answer) {
    const result = new ValidationResult();
    
    const answerValidation = validateInput(answer, 'securityAnswer', VALIDATION_CONFIG.SECURITY_ANSWER);
    if (answerValidation.hasErrors()) {
        result.errors.push(...answerValidation.errors);
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Express middleware for data validation
 */
function validateDataMiddleware(validationFunction) {
    return (req, res, next) => {
        try {
            const validationResult = validationFunction(req.body);
            
            if (!validationResult.isValid) {
                logValidationEvent('error', 'Data validation failed', {
                    errors: validationResult.errors,
                    rejectedFields: validationResult.getRejectedFields(),
                    userAgent: req.get('User-Agent'),
                    ip: req.ip
                });
                
                return res.status(400).json({
                    success: false,
                    error: 'Data validation failed',
                    details: validationResult.errors,
                    rejectedFields: validationResult.getRejectedFields()
                });
            }
            
            next();
        } catch (error) {
            logValidationEvent('error', 'Validation middleware error', {
                error: error.message,
                stack: error.stack
            });
            
            return res.status(500).json({
                success: false,
                error: 'Internal validation error'
            });
        }
    };
}

/**
 * Validate course data
 */
function validateCourse(data) {
    const result = new ValidationResult();
    
    // Validate course name
    const nameValidation = validateInput(data.name, 'name', VALIDATION_CONFIG.COURSE.NAME);
    if (nameValidation.hasErrors()) {
        result.errors.push(...nameValidation.errors);
    }
    
    // Validate course code
    const codeValidation = validateInput(data.code, 'code', VALIDATION_CONFIG.COURSE.CODE);
    if (codeValidation.hasErrors()) {
        result.errors.push(...codeValidation.errors);
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

/**
 * Validate subject data
 */
function validateSubject(data) {
    const result = new ValidationResult();
    
    // Validate subject name
    const nameValidation = validateInput(data.name, 'name', VALIDATION_CONFIG.COURSE.NAME);
    if (nameValidation.hasErrors()) {
        result.errors.push(...nameValidation.errors);
    }
    
    // Validate subject code
    const codeValidation = validateInput(data.code, 'code', VALIDATION_CONFIG.COURSE.CODE);
    if (codeValidation.hasErrors()) {
        result.errors.push(...codeValidation.errors);
    }
    
    result.isValid = result.errors.length === 0;
    return result;
}

// Export all validation functions and configuration
module.exports = {
    VALIDATION_CONFIG,
    ValidationResult,
    validateInput,
    validateUserRegistration,
    validateReviewCreation,
    validateProfileEdit,
    validateSearchQuery,
    validateComment,
    validateSecurityAnswer,
    validateCourse,
    validateSubject,
    validateDataMiddleware,
    logValidationEvent
};
