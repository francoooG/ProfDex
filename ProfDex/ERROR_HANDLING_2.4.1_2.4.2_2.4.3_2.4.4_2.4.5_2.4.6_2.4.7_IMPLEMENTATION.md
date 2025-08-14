# Error Handling and Logging Implementation

## Overview

This document describes the implementation of comprehensive error handling and logging system for the ProfDex application, covering all requirements from section 2.4 of the security specifications.

## Requirements Implemented

### 2.4.1. Use error handlers that do not display debugging or stack trace information
### 2.4.2. Implement generic error messages and use custom error pages
### 2.4.3. Logging controls should support both success and failure of specified security events
### 2.4.4. Restrict access to logs to only website administrators
### 2.4.5. Log all input validation failures
### 2.4.6. Log all authentication attempts, especially failures
### 2.4.7. Log all access control failures

## Architecture

### Core Components

1. **`error_handling.js`** - Centralized error handling and logging system
2. **`views/error.hbs`** - Custom error page template
3. **`views/admin_logs.hbs`** - Administrator log viewing interface
4. **Integration with existing systems** - Auth, data validation, and business rules

### Database Schema

```javascript
// LogEntry Schema (MongoDB)
{
    timestamp: Date,           // When the event occurred
    level: String,            // error, warn, info, debug
    eventType: String,        // authentication, authorization, validation, access_control, system, user_action
    message: String,          // Human-readable message
    details: Object,          // Additional context
    userId: ObjectId,         // Reference to User (if applicable)
    userType: String,         // Type of user involved
    ipAddress: String,        // IP address of the request
    userAgent: String,        // User agent string
    requestPath: String,      // Requested URL path
    requestMethod: String,    // HTTP method
    sessionId: String,        // Session identifier
    success: Boolean,         // Whether the operation succeeded
    errorCode: String,        // Error code (if applicable)
    duration: Number          // Request duration in milliseconds
}
```

## Implementation Details

### 2.4.1 & 2.4.2: Error Handling Without Debugging Information

**File: `error_handling.js`**

```javascript
function handleError(error, req, res, next) {
    // Don't expose internal error details in production
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    // Log the error internally (with full details)
    logSecurityEvent('error', 'Application error occurred', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.session?.user?._id,
        userType: req.session?.user?.userType
    });
    
    // Determine appropriate error response
    let statusCode = 500;
    let errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.server_error;
    
    // Map specific errors to generic messages
    if (error.type === 'entity.parse.failed') {
        statusCode = 400;
        errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.validation_failed;
    } else if (error.code === 'ENOENT') {
        statusCode = 404;
        errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.not_found;
    }
    
    // Send appropriate response
    if (req.xhr || req.headers.accept?.includes('application/json')) {
        // API request - return JSON
        res.status(statusCode).json({
            error: errorMessage,
            status: statusCode,
            timestamp: new Date().toISOString()
        });
    } else {
        // Browser request - render error page
        res.status(statusCode).render('error', {
            errorCode: statusCode,
            errorTitle: ERROR_CONFIG.ERROR_PAGES[statusCode] || 'Error',
            errorMessage: errorMessage,
            layout: false
        });
    }
}
```

**File: `views/error.hbs`**

- Custom error page with user-friendly design
- No technical details exposed to users
- Contextual help based on error type
- Navigation options for recovery

### 2.4.3: Security Event Logging

**File: `error_handling.js`**

```javascript
async function logSecurityEvent(level, message, details = {}) {
    try {
        const logEntry = new LogEntry({
            level,
            eventType: details.eventType || ERROR_CONFIG.SECURITY_EVENTS.SYSTEM,
            message,
            details,
            userId: details.userId || null,
            userType: details.userType || null,
            ipAddress: details.ipAddress || null,
            userAgent: details.userAgent || null,
            requestPath: details.requestPath || null,
            requestMethod: details.requestMethod || null,
            sessionId: details.sessionId || null,
            success: details.success !== false,
            errorCode: details.errorCode || null,
            duration: details.duration || null
        });
        
        await logEntry.save();
        
        // Also log to console for development
        if (process.env.NODE_ENV === 'development') {
            console.log(`[${level.toUpperCase()}] ${message}`, details);
        }
    } catch (error) {
        // Fallback to console if database logging fails
        console.error('Failed to log security event:', error);
        console.log(`[${level.toUpperCase()}] ${message}`, details);
    }
}
```

### 2.4.4: Administrator-Only Log Access

**File: `index.js`**

```javascript
// Admin logs routes - restrict access to logs to only website administrators
app.route('/admin/logs')
.get(isAdministrator, async (req, res) => {
    try {
        res.render(__dirname + '/views' + '/admin_logs.hbs', {
            layout: false,
            loggedInUser: req.session.user
        });
    } catch (error) {
        console.error('Error loading admin logs: ', error);
        res.status(500).send('Server error');
    }
});

// API endpoint to get logs data
app.get('/admin/logs/data', isAdministrator, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 50;
        const skip = (page - 1) * limit;
        
        const filters = {};
        if (req.query.level) filters.level = req.query.level;
        if (req.query.eventType) filters.eventType = req.query.eventType;
        if (req.query.success !== undefined) filters.success = req.query.success === 'true';
        if (req.query.startDate) filters.startDate = req.query.startDate;
        if (req.query.endDate) filters.endDate = req.query.endDate;
        
        const result = await getLogs(filters, limit, skip);
        
        res.json({
            success: true,
            logs: result.logs,
            page: result.page,
            totalPages: result.totalPages,
            total: result.total
        });
    } catch (error) {
        console.error('Error fetching logs:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch logs'
        });
    }
});
```

**File: `views/admin_logs.hbs`**

- Real-time log viewing interface
- Filtering by level, event type, success status, and date range
- Pagination for large log datasets
- Export functionality (CSV)
- Statistics dashboard
- Responsive design

### 2.4.5: Input Validation Failure Logging

**File: `data_validation.js`**

```javascript
function logValidationEvent(level, message, details = {}) {
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
```

**Integration Points:**
- User registration validation
- Review creation validation
- Profile edit validation
- Search query validation
- Security answer validation
- SQL injection detection
- XSS pattern detection

### 2.4.6: Authentication Attempt Logging

**File: `index.js`**

```javascript
if (loggedInUser) {
    // Check for account locked error
    if (loggedInUser.error === 'account_locked') {
        // 2.4.6: Log failed authentication attempt (account locked)
        await logAuthenticationAttempt(false, {
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            email: email,
            sessionId: req.sessionID,
            requestPath: req.path,
            requestMethod: req.method,
            error: 'Account locked',
            reason: loggedInUser.reason
        });
        
        res.redirect(`/login?error=account_locked&reason=${encodeURIComponent(loggedInUser.reason)}`);
        return;
    }

    // 2.4.6: Log successful authentication attempt
    await logAuthenticationAttempt(true, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        userId: loggedInUser._id,
        userType: loggedInUser.userType,
        sessionId: req.sessionID,
        requestPath: req.path,
        requestMethod: req.method
    });
    
    // ... rest of successful login logic
} else {
    // 2.4.6: Log failed authentication attempt
    await logAuthenticationAttempt(false, {
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        email: email,
        sessionId: req.sessionID,
        requestPath: req.path,
        requestMethod: req.method,
        error: 'Invalid credentials'
    });
    
    res.redirect('/login?error=authentication_failed');
    return;
}
```

**File: `error_handling.js`**

```javascript
async function logAuthenticationAttempt(success, details) {
    await logSecurityEvent(
        success ? 'info' : 'warn',
        success ? 'Authentication successful' : 'Authentication failed',
        {
            eventType: ERROR_CONFIG.SECURITY_EVENTS.AUTHENTICATION,
            success,
            ...details
        }
    );
}
```

### 2.4.7: Access Control Failure Logging

**File: `auth.js`**

```javascript
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
    
    // 2.4.7: Log all access control failures
    if (level === 'error' || level === 'warn') {
        // Import the logging function dynamically to avoid circular dependencies
        const { logAccessControlFailure } = require('./error_handling');
        logAccessControlFailure({
            message,
            details: logEntry.context,
            level,
            timestamp: new Date(),
            component: 'authorization'
        }).catch(err => {
            console.error('Failed to log security event:', err);
        });
    }
}
```

**Integration Points:**
- Session validation failures
- Role-based access control failures
- Resource ownership validation failures
- Action-based authorization failures
- Fail-secure principle enforcement

## Middleware Integration

### Request Logging Middleware

```javascript
function requestLoggingMiddleware() {
    return (req, res, next) => {
        const startTime = Date.now();
        
        // Log the request completion
        res.on('finish', () => {
            const duration = Date.now() - startTime;
            const success = res.statusCode < 400;
            
            logSecurityEvent(
                success ? 'info' : 'warn',
                `${req.method} ${req.path} - ${res.statusCode}`,
                {
                    eventType: ERROR_CONFIG.SECURITY_EVENTS.SYSTEM,
                    success,
                    requestPath: req.path,
                    requestMethod: req.method,
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    userId: req.session?.user?._id,
                    userType: req.session?.user?.userType,
                    sessionId: req.sessionID,
                    duration,
                    statusCode: res.statusCode
                }
            );
        });
        
        next();
    };
}
```

### Error Handling Middleware

```javascript
function errorHandlingMiddleware() {
    return (error, req, res, next) => {
        handleError(error, req, res, next);
    };
}
```

## Log Management Features

### Statistics and Analytics

```javascript
async function getLogStatistics() {
    try {
        const stats = await LogEntry.aggregate([
            {
                $group: {
                    _id: null,
                    totalLogs: { $sum: 1 },
                    errorLogs: { $sum: { $cond: [{ $eq: ['$level', 'error'] }, 1, 0] } },
                    warnLogs: { $sum: { $cond: [{ $eq: ['$level', 'warn'] }, 1, 0] } },
                    infoLogs: { $sum: { $cond: [{ $eq: ['$level', 'info'] }, 1, 0] } },
                    failedAuthAttempts: { 
                        $sum: { 
                            $cond: [
                                { 
                                    $and: [
                                        { $eq: ['$eventType', 'authentication'] },
                                        { $eq: ['$success', false] }
                                    ]
                                }, 
                                1, 
                                0 
                            ] 
                        } 
                    },
                    failedAccessAttempts: {
                        $sum: {
                            $cond: [
                                {
                                    $and: [
                                        { $eq: ['$eventType', 'access_control'] },
                                        { $eq: ['$success', false] }
                                    ]
                                },
                                1,
                                0
                            ]
                        }
                    },
                    validationFailures: {
                        $sum: {
                            $cond: [
                                {
                                    $and: [
                                        { $eq: ['$eventType', 'validation'] },
                                        { $eq: ['$success', false] }
                                    ]
                                },
                                1,
                                0
                            ]
                        }
                    }
                }
            }
        ]);
        
        return {
            ...stats[0],
            recentActivity,
            topEventTypes
        };
    } catch (error) {
        console.error('Error fetching log statistics:', error);
        throw new Error('Failed to fetch log statistics');
    }
}
```

### Log Cleanup

```javascript
async function cleanupOldLogs(daysToKeep = 30) {
    try {
        const cutoffDate = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000);
        const result = await LogEntry.deleteMany({
            timestamp: { $lt: cutoffDate }
        });
        
        await logSecurityEvent('info', 'Old logs cleaned up', {
            eventType: ERROR_CONFIG.SECURITY_EVENTS.SYSTEM,
            success: true,
            deletedCount: result.deletedCount,
            cutoffDate
        });
        
        return result.deletedCount;
    } catch (error) {
        console.error('Error cleaning up old logs:', error);
        throw new Error('Failed to cleanup old logs');
    }
}
```

## Security Features

### Data Protection

1. **No Sensitive Data Exposure**: Passwords and sensitive information are never logged
2. **IP Address Tracking**: All requests are logged with IP addresses for security monitoring
3. **Session Tracking**: Session IDs are logged for correlation analysis
4. **User Agent Logging**: Browser/client information is captured for threat detection

### Access Control

1. **Administrator-Only Access**: Log viewing is restricted to administrators only
2. **API Protection**: All log-related endpoints require administrator authentication
3. **CSRF Protection**: Log export and management functions are protected
4. **Rate Limiting**: Log API endpoints are protected against abuse

### Audit Trail

1. **Comprehensive Logging**: All security-relevant events are logged
2. **Success/Failure Tracking**: Both successful and failed operations are recorded
3. **Context Preservation**: Full context is maintained for investigation
4. **Timestamp Accuracy**: All events are timestamped with high precision

## Configuration

### Environment Variables

```javascript
// Error handling configuration
const ERROR_CONFIG = {
    GENERIC_MESSAGES: {
        authentication_failed: 'Authentication failed. Please check your credentials.',
        authorization_denied: 'Access denied. You do not have permission to perform this action.',
        validation_failed: 'Invalid input provided. Please check your data and try again.',
        server_error: 'An unexpected error occurred. Please try again later.',
        not_found: 'The requested resource was not found.',
        database_error: 'Database operation failed. Please try again later.',
        session_expired: 'Your session has expired. Please log in again.',
        rate_limit_exceeded: 'Too many requests. Please wait before trying again.',
        maintenance_mode: 'System is under maintenance. Please try again later.'
    },
    
    ERROR_PAGES: {
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Page Not Found',
        500: 'Internal Server Error',
        503: 'Service Unavailable'
    },
    
    LOG_LEVELS: {
        ERROR: 'error',
        WARN: 'warn',
        INFO: 'info',
        DEBUG: 'debug'
    },
    
    SECURITY_EVENTS: {
        AUTHENTICATION: 'authentication',
        AUTHORIZATION: 'authorization',
        VALIDATION: 'validation',
        ACCESS_CONTROL: 'access_control',
        SYSTEM: 'system',
        USER_ACTION: 'user_action'
    }
};
```

## Benefits

### Security Monitoring

1. **Real-time Threat Detection**: Suspicious patterns can be identified quickly
2. **Attack Pattern Analysis**: Failed authentication attempts and access control violations are tracked
3. **User Behavior Analysis**: Normal vs. abnormal user behavior can be distinguished
4. **Compliance Reporting**: Comprehensive audit trails for regulatory compliance

### Operational Excellence

1. **Proactive Issue Detection**: Problems can be identified before they affect users
2. **Performance Monitoring**: Request duration and success rates are tracked
3. **Debugging Support**: Detailed logs for troubleshooting (in development)
4. **Capacity Planning**: Usage patterns inform infrastructure decisions

### User Experience

1. **Generic Error Messages**: Users see helpful, non-technical error messages
2. **Graceful Error Handling**: Application continues to function even when errors occur
3. **Recovery Guidance**: Error pages provide clear next steps for users
4. **Consistent Experience**: All errors are handled uniformly across the application

## Testing

### Test Scenarios

1. **Authentication Logging**: Test successful and failed login attempts
2. **Access Control Logging**: Test unauthorized access attempts
3. **Validation Logging**: Test input validation failures
4. **Error Handling**: Test various error conditions and responses
5. **Admin Log Access**: Test administrator-only log viewing
6. **Log Export**: Test CSV export functionality
7. **Log Cleanup**: Test automatic log cleanup

### Validation Checklist

- [ ] No debugging information exposed to users
- [ ] Generic error messages displayed
- [ ] Custom error pages rendered correctly
- [ ] All authentication attempts logged
- [ ] All access control failures logged
- [ ] All validation failures logged
- [ ] Logs accessible only to administrators
- [ ] Log export functionality works
- [ ] Log statistics are accurate
- [ ] Log cleanup operates correctly

## Conclusion

The error handling and logging system provides comprehensive security monitoring and user experience improvements while maintaining strict access controls and data protection. The implementation satisfies all requirements from section 2.4 of the security specifications and provides a solid foundation for ongoing security monitoring and incident response.
