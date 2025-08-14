# Business Rules Enforcement Implementation (2.2.3)

## Overview

This document describes the implementation of **2.2.3. Enforce application logic flows to comply with business rules** in the ProfDex application. The business rules enforcement system ensures that all application operations follow proper business logic and prevent unauthorized or illogical operations.

## Key Business Rules Implemented

### 1. Review Creation Rules
- **Students Only**: Only students can create reviews
- **One Review Per Professor**: Each student can only create one review per professor
- **No Self-Review**: Professors cannot review themselves
- **Text Length Validation**: Review text must be between 10-2000 characters
- **Rating Validation**: All ratings must be between 1-5

### 2. Review Management Rules
- **Ownership Validation**: Users can only edit/delete their own reviews
- **Moderator Privileges**: Managers and administrators can moderate all reviews
- **Resource Existence**: Reviews must exist before modification/deletion

### 3. Profile Management Rules
- **Name Validation**: Names must be between 2-50 characters
- **Email Validation**: Email format must be valid and unique
- **Bio Length**: Bio must not exceed 500 characters
- **User Type Consistency**: Profile updates must match user type

### 4. User Type Validation
- **Valid User Types**: Only 'student', 'professor', 'manager', 'administrator' allowed
- **Required Fields**: Each user type has specific required fields
- **Data Integrity**: User data must be consistent across collections

## Implementation Details

### Business Rules Configuration (`business_rules.js`)

#### Configuration Object
```javascript
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
```

#### Core Validation Functions

**1. User Business Rules Validation**
```javascript
async function validateUserBusinessRules(user, operation, context = {}) {
    // Validates user existence and type
    // Checks operation-specific business rules
    // Returns validation result with error details
}
```

**2. Operation-Specific Validation**
```javascript
async function validateOperationBusinessRules(user, operation, context = {}) {
    // Routes to specific validation functions based on operation
    // Supports: create_review, edit_review, delete_review, edit_profile
}
```

**3. Review Creation Validation**
```javascript
async function validateReviewCreationRules(user, context) {
    // Validates student-only restriction
    // Checks for duplicate reviews
    // Validates text length and ratings
    // Prevents self-review by professors
}
```

**4. Review Management Validation**
```javascript
async function validateReviewEditRules(user, context) {
    // Validates review ownership
    // Checks moderator privileges
    // Ensures review exists
}

async function validateReviewDeletionRules(user, context) {
    // Validates review ownership
    // Checks moderator privileges
    // Prevents system-critical review deletion
}
```

**5. Profile Edit Validation**
```javascript
async function validateProfileEditRules(user, context) {
    // Validates name length requirements
    // Checks email format and uniqueness
    // Validates bio length
}
```

#### Business Rules Middleware
```javascript
function enforceBusinessRulesMiddleware(operation, contextProvider = null) {
    return async (req, res, next) => {
        // Validates business rules before operation execution
        // Provides detailed error messages for violations
        // Logs business rule events for monitoring
    };
}
```

### Integration with Application Routes

#### Review Creation Route
```javascript
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
    // Business rules validated before execution
    // Simplified route logic
    // Enhanced logging
});
```

#### Profile Edit Route
```javascript
.post(isLoggedIn, enforceBusinessRulesMiddleware('edit_profile', (req) => ({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    bio: req.body.bio
})), async (req, res) => {
    // Business rules validated before execution
    // Simplified route logic
    // Enhanced logging
});
```

#### Review Deletion Route
```javascript
app.post('/delete-review-and-comments', isLoggedIn, enforceBusinessRulesMiddleware('delete_review', (req) => ({
    reviewId: req.body.reviewId
})), async (req, res) => {
    // Business rules validated before execution
    // Simplified route logic
    // Enhanced logging
});
```

## Business Rules Enforcement Features

### 1. Centralized Validation
- All business rules are defined in a single configuration
- Consistent validation across all operations
- Easy to modify and extend business rules

### 2. Comprehensive Logging
- All business rule violations are logged
- Successful operations are logged for audit trails
- Detailed context information for debugging

### 3. Detailed Error Messages
- User-friendly error messages
- Specific details about rule violations
- Consistent error handling across the application

### 4. Operation-Specific Validation
- Different validation rules for different operations
- Context-aware validation
- Flexible validation framework

### 5. Security Integration
- Works with existing authorization system
- Prevents unauthorized operations
- Maintains security while enforcing business rules

## Business Rules Examples

### Review Creation Validation
```javascript
// Student attempting to create review
const validation = await validateReviewCreationRules(student, {
    professorId: 'professor123',
    text: 'Great professor!',
    ratings: { generosity: 4, difficulty: 3, engagement: 5, proficiency: 4, workload: 3 }
});
// Result: { isValid: true }

// Professor attempting to create review
const validation = await validateReviewCreationRules(professor, {
    professorId: 'professor123',
    text: 'Great professor!'
});
// Result: { isValid: false, error: 'Only students can create reviews' }

// Student attempting duplicate review
const validation = await validateReviewCreationRules(student, {
    professorId: 'professor123', // Already reviewed
    text: 'Another review'
});
// Result: { isValid: false, error: 'You already have a review for this professor' }
```

### Profile Edit Validation
```javascript
// Valid profile update
const validation = await validateProfileEditRules(user, {
    firstName: 'John',
    lastName: 'Doe',
    email: 'john.doe@email.com',
    bio: 'Student at university'
});
// Result: { isValid: true }

// Invalid email format
const validation = await validateProfileEditRules(user, {
    email: 'invalid-email'
});
// Result: { isValid: false, error: 'Invalid email format' }

// Duplicate email
const validation = await validateProfileEditRules(user, {
    email: 'existing@email.com' // Already taken
});
// Result: { isValid: false, error: 'Email is already taken by another user' }
```

## Benefits of Business Rules Implementation

### 1. Data Integrity
- Prevents invalid data from being stored
- Ensures consistency across the application
- Maintains referential integrity

### 2. Security Enhancement
- Prevents unauthorized operations
- Validates user permissions
- Protects against business logic attacks

### 3. User Experience
- Clear error messages for violations
- Consistent behavior across operations
- Prevents user confusion

### 4. Maintainability
- Centralized business logic
- Easy to modify rules
- Clear separation of concerns

### 5. Audit and Compliance
- Comprehensive logging of operations
- Business rule violation tracking
- Audit trail for compliance

## Testing and Validation

### Business Rules Testing
1. **Review Creation Tests**: Verify student-only restriction, duplicate prevention, text validation
2. **Profile Edit Tests**: Verify name/email validation, uniqueness checks
3. **Review Management Tests**: Verify ownership validation, moderator privileges
4. **User Type Tests**: Verify valid user types and required fields

### Integration Testing
1. **Route Protection**: Verify all routes are properly protected
2. **Error Handling**: Test business rule violation responses
3. **Logging Validation**: Verify all events are properly logged
4. **Performance Testing**: Ensure business rules don't impact performance

## Future Enhancements

### 1. Advanced Business Rules
- **Workflow Rules**: Enforce business process workflows
- **State Validation**: Ensure operations are performed in valid states
- **Conditional Rules**: Rules that depend on user context or system state

### 2. Business Rules Engine
- **Rule Engine**: More sophisticated rule processing
- **Dynamic Rules**: Rules that can be modified without code changes
- **Rule Versioning**: Track changes to business rules over time

### 3. Enhanced Monitoring
- **Real-time Monitoring**: Monitor business rule violations in real-time
- **Analytics**: Analyze business rule patterns and trends
- **Alerting**: Automatic alerts for critical rule violations

## Conclusion

The business rules enforcement implementation provides comprehensive validation for all application operations. By centralizing business logic and providing detailed validation, the system ensures data integrity, security, and consistent user experience.

The implementation includes:
- Centralized business rules configuration
- Operation-specific validation functions
- Comprehensive logging and monitoring
- Integration with existing security systems
- Detailed error handling and user feedback

This implementation satisfies requirement **2.2.3. Enforce application logic flows to comply with business rules** and provides a solid foundation for future business rule enhancements.
