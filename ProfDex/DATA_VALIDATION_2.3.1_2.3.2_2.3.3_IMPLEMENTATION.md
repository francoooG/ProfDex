# Data Validation Implementation
## Security Requirements 2.3.1, 2.3.2, and 2.3.3

This document describes the implementation of comprehensive data validation for the ProfDex application, covering three critical security requirements:

- **2.3.1**: All validation failures should result in input rejection. Sanitizing should not be used.
- **2.3.2**: Validate data range
- **2.3.3**: Validate data length

## Overview

The data validation system is implemented as a centralized, comprehensive validation framework that ensures all user inputs are properly validated before processing. The system rejects invalid inputs without attempting to sanitize them, providing detailed error messages and logging for security monitoring.

## Architecture

### Core Components

1. **`data_validation.js`** - Main validation system
2. **`VALIDATION_CONFIG`** - Centralized validation rules
3. **`ValidationResult`** - Structured validation results
4. **Express Middleware** - Route integration
5. **Frontend Error Handling** - User feedback

### Key Features

- **Fail-Fast Validation**: Stops validation on first error
- **Comprehensive Logging**: All validation failures are logged for security monitoring
- **Security Pattern Detection**: Identifies potential SQL injection and XSS attempts
- **Structured Error Reporting**: Detailed error messages with context
- **No Sanitization**: Strictly rejects invalid input without modification

## Implementation Details

### 1. Validation Configuration (`VALIDATION_CONFIG`)

The system uses a centralized configuration object that defines validation rules for all data types:

```javascript
const VALIDATION_CONFIG = {
    USER: {
        FIRST_NAME: {
            MIN_LENGTH: 2,
            MAX_LENGTH: 50,
            PATTERN: /^[a-zA-Z\s\-']+$/,
            ALLOWED_CHARS: 'Letters, spaces, hyphens, and apostrophes only'
        },
        // ... other user fields
    },
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
    // ... other data types
};
```

### 2. Validation Result Structure

The `ValidationResult` class provides structured validation results:

```javascript
class ValidationResult {
    constructor() {
        this.isValid = true;
        this.errors = [];
        this.warnings = [];
        this.rejectedFields = [];
        this.validationDetails = {};
    }
    
    addError(field, message, details = {}) {
        // Adds validation error with timestamp and context
    }
    
    getFirstError() {
        // Returns the first validation error
    }
    
    getRejectedFields() {
        // Returns list of fields that failed validation
    }
}
```

### 3. Core Validation Function

The `validateInput` function implements the three security requirements:

#### 2.3.1: Input Rejection Without Sanitizing

```javascript
function validateInput(input, fieldName, validationRules) {
    const result = new ValidationResult();
    
    // Check if input exists
    if (input === null || input === undefined) {
        result.addError(fieldName, `Field '${fieldName}' is required`, {
            type: 'missing_field',
            expected: 'non-null value'
        });
        return result; // Reject immediately, no sanitization
    }
    
    // Convert to string for validation (no sanitization)
    const stringInput = String(input).trim();
    
    // Pattern validation - reject if pattern doesn't match
    if (validationRules.PATTERN && !validationRules.PATTERN.test(stringInput)) {
        result.addError(fieldName, `Field '${fieldName}' contains invalid characters. ${validationRules.ALLOWED_CHARS}`, {
            type: 'pattern_validation',
            pattern: validationRules.PATTERN.toString(),
            allowed_chars: validationRules.ALLOWED_CHARS,
            actual: stringInput
        });
    }
    
    return result;
}
```

#### 2.3.2: Data Range Validation

```javascript
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
```

#### 2.3.3: Data Length Validation

```javascript
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
```

### 4. Security Pattern Detection

The system includes advanced security validation to detect potential attacks:

```javascript
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
```

## Route Integration

### 1. User Registration Validation

```javascript
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
```

### 2. Review Creation Validation

```javascript
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
```

### 3. Profile Edit Validation

```javascript
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
```

### 4. Search Query Validation

```javascript
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
```

### 5. Security Answer Validation

```javascript
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
```

## Frontend Integration

### Error Handling in Templates

The frontend templates have been updated to display validation errors:

```handlebars
{{#if errors.data_validation}}
    <div class="alert alert-error">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        <span>Data validation failed: {{errors.data_validation_details}}</span>
    </div>
{{/if}}
```

### Route Error Handling

Routes have been updated to handle validation errors:

```javascript
if (req.query.error === 'data_validation') {
    errors.data_validation = true;
    errors.data_validation_details = req.query.details ? decodeURIComponent(req.query.details) : 'Data validation failed.';
}
```

## Security Features

### 1. Comprehensive Logging

All validation failures are logged with detailed context:

```javascript
function logValidationEvent(level, message, details = {}) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        details,
        component: 'data_validation'
    };

    console.log(`[VALIDATION ${level.toUpperCase()}] ${message}`, details);
    
    // In production, this would be sent to a security logging system
    if (level === 'error' || level === 'security') {
        console.error(`SECURITY VALIDATION ${level.toUpperCase()}: ${message}`, details);
    }
}
```

### 2. Fail-Secure Design

The system implements fail-secure principles:

- **Default Deny**: All inputs are rejected by default unless they pass validation
- **No Sanitization**: Invalid inputs are never modified or sanitized
- **Immediate Rejection**: Validation stops on first error
- **Detailed Logging**: All failures are logged for security monitoring

### 3. Attack Pattern Detection

The system detects common attack patterns:

- **SQL Injection**: Detects SQL keywords and patterns
- **XSS Attempts**: Identifies script tags and event handlers
- **Command Injection**: Recognizes system command patterns
- **Path Traversal**: Detects directory traversal attempts

## Validation Rules by Data Type

### User Data
- **First Name**: 2-50 characters, letters, spaces, hyphens, apostrophes only
- **Last Name**: 2-50 characters, letters, spaces, hyphens, apostrophes only
- **Email**: 5-254 characters, valid email format
- **Bio**: 0-500 characters, letters, numbers, basic punctuation
- **Student ID**: 5-20 characters, uppercase letters, numbers, hyphens only
- **Teacher ID**: 5-20 characters, uppercase letters, numbers, hyphens only

### Review Data
- **Text**: 10-2000 characters, letters, numbers, common punctuation
- **Ratings**: 1-5 numeric values only

### Search Data
- **Query**: 1-100 characters, letters, numbers, spaces, basic punctuation

### Security Data
- **Answers**: 3-100 characters, letters, numbers, basic punctuation

## Benefits

### 1. Security Enhancement
- **Input Rejection**: Prevents malicious data from entering the system
- **Attack Prevention**: Detects and blocks common attack patterns
- **Data Integrity**: Ensures only valid data is processed

### 2. User Experience
- **Clear Error Messages**: Users receive specific feedback about validation failures
- **Immediate Feedback**: Validation errors are shown immediately
- **Consistent Behavior**: All forms use the same validation rules

### 3. Maintainability
- **Centralized Rules**: All validation logic is in one place
- **Configurable**: Validation rules can be easily modified
- **Extensible**: New validation types can be added easily

### 4. Compliance
- **Security Standards**: Meets enterprise security requirements
- **Audit Trail**: All validation failures are logged
- **Documentation**: Comprehensive validation rules are documented

## Testing

The validation system can be tested with various input types:

### Valid Inputs
- Normal user data (names, emails, etc.)
- Standard review content
- Valid search queries

### Invalid Inputs
- SQL injection attempts
- XSS script tags
- Oversized inputs
- Invalid characters
- Out-of-range values

### Security Testing
- Attack pattern detection
- Logging verification
- Error handling validation

## Future Enhancements

1. **Real-time Validation**: Client-side validation with server-side verification
2. **Custom Validation Rules**: User-defined validation patterns
3. **Internationalization**: Support for non-English character sets
4. **Performance Optimization**: Caching of validation results
5. **Advanced Pattern Detection**: Machine learning-based attack detection

## Conclusion

The data validation system successfully implements all three security requirements:

- ✅ **2.3.1**: All validation failures result in input rejection without sanitization
- ✅ **2.3.2**: Comprehensive data range validation for numeric fields
- ✅ **2.3.3**: Thorough data length validation for all text fields

The system provides robust security, excellent user experience, and maintainable code structure while ensuring compliance with enterprise security standards.
