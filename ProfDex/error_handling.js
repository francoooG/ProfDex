const mongoose = require('mongoose');

// 2.4.1, 2.4.2: Error handling configuration - no debugging/stack trace, generic messages
const ERROR_CONFIG = {
    // Generic error messages for different scenarios
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
    
    // Error page templates
    ERROR_PAGES: {
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Page Not Found',
        500: 'Internal Server Error',
        503: 'Service Unavailable'
    },
    
    // Logging levels
    LOG_LEVELS: {
        ERROR: 'error',
        WARN: 'warn',
        INFO: 'info',
        DEBUG: 'debug'
    },
    
    // Security event types
    SECURITY_EVENTS: {
        AUTHENTICATION: 'authentication',
        AUTHORIZATION: 'authorization',
        VALIDATION: 'validation',
        ACCESS_CONTROL: 'access_control',
        SYSTEM: 'system',
        USER_ACTION: 'user_action'
    }
};

// 2.4.3, 2.4.4, 2.4.5, 2.4.6, 2.4.7: Logging schema for MongoDB storage
const logEntrySchema = new mongoose.Schema({
    timestamp: {
        type: Date,
        default: Date.now,
        required: true
    },
    level: {
        type: String,
        enum: Object.values(ERROR_CONFIG.LOG_LEVELS),
        required: true
    },
    eventType: {
        type: String,
        enum: Object.values(ERROR_CONFIG.SECURITY_EVENTS),
        required: true
    },
    message: {
        type: String,
        required: true
    },
    details: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    userType: {
        type: String,
        default: null
    },
    ipAddress: {
        type: String,
        default: null
    },
    userAgent: {
        type: String,
        default: null
    },
    requestPath: {
        type: String,
        default: null
    },
    requestMethod: {
        type: String,
        default: null
    },
    sessionId: {
        type: String,
        default: null
    },
    success: {
        type: Boolean,
        required: true
    },
    errorCode: {
        type: String,
        default: null
    },
    duration: {
        type: Number, // milliseconds
        default: null
    }
});

// Index for efficient querying
logEntrySchema.index({ timestamp: -1 });
logEntrySchema.index({ level: 1, timestamp: -1 });
logEntrySchema.index({ eventType: 1, timestamp: -1 });
logEntrySchema.index({ userId: 1, timestamp: -1 });
logEntrySchema.index({ success: 1, timestamp: -1 });

const LogEntry = mongoose.model('LogEntry', logEntrySchema);

// 2.4.1, 2.4.2: Generic error handler - no debugging/stack trace information
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
    
    if (error.status) {
        statusCode = error.status;
    }
    
    if (error.type === 'entity.parse.failed') {
        statusCode = 400;
        errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.validation_failed;
    } else if (error.code === 'ENOENT') {
        statusCode = 404;
        errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.not_found;
    } else if (error.name === 'ValidationError') {
        statusCode = 400;
        errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.validation_failed;
    } else if (error.name === 'CastError') {
        statusCode = 400;
        errorMessage = ERROR_CONFIG.GENERIC_MESSAGES.validation_failed;
    } else if (error.name === 'MongoError' && error.code === 11000) {
        statusCode = 409;
        errorMessage = 'Resource already exists.';
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

// 2.4.3, 2.4.5, 2.4.6, 2.4.7: Centralized security event logging
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
            success: details.success !== false, // Default to true unless explicitly false
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

// 2.4.6: Log authentication attempts (success and failure)
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

// 2.4.7: Log access control failures
async function logAccessControlFailure(details) {
    await logSecurityEvent('warn', 'Access control failure', {
        eventType: ERROR_CONFIG.SECURITY_EVENTS.ACCESS_CONTROL,
        success: false,
        ...details
    });
}

// 2.4.5: Log input validation failures
async function logValidationFailure(details) {
    await logSecurityEvent('warn', 'Input validation failed', {
        eventType: ERROR_CONFIG.SECURITY_EVENTS.VALIDATION,
        success: false,
        ...details
    });
}

// 2.4.4: Get logs for administrators only
async function getLogs(filters = {}, limit = 100, skip = 0) {
    try {
        const query = {};
        
        // Apply filters
        if (filters.level) {
            query.level = filters.level;
        }
        if (filters.eventType) {
            query.eventType = filters.eventType;
        }
        if (filters.success !== undefined) {
            query.success = filters.success;
        }
        if (filters.userId) {
            query.userId = filters.userId;
        }
        if (filters.startDate) {
            query.timestamp = { $gte: new Date(filters.startDate) };
        }
        if (filters.endDate) {
            if (query.timestamp) {
                query.timestamp.$lte = new Date(filters.endDate);
            } else {
                query.timestamp = { $lte: new Date(filters.endDate) };
            }
        }
        
        const logs = await LogEntry.find(query)
            .sort({ timestamp: -1 })
            .limit(limit)
            .skip(skip)
            .populate('userId', 'firstName lastName email')
            .lean();
            
        const total = await LogEntry.countDocuments(query);
        
        return {
            logs,
            total,
            page: Math.floor(skip / limit) + 1,
            totalPages: Math.ceil(total / limit)
        };
    } catch (error) {
        console.error('Error fetching logs:', error);
        throw new Error('Failed to fetch logs');
    }
}

// 2.4.4: Get log statistics for administrators
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
        
        // Get recent activity (last 24 hours)
        const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentActivity = await LogEntry.countDocuments({
            timestamp: { $gte: last24Hours }
        });
        
        // Get top event types
        const topEventTypes = await LogEntry.aggregate([
            {
                $group: {
                    _id: '$eventType',
                    count: { $sum: 1 }
                }
            },
            {
                $sort: { count: -1 }
            },
            {
                $limit: 5
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

// 2.4.4: Clean up old logs (keep last 30 days by default)
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

// Express middleware for error handling
function errorHandlingMiddleware() {
    return (error, req, res, next) => {
        handleError(error, req, res, next);
    };
}

// Express middleware for request logging
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

module.exports = {
    ERROR_CONFIG,
    LogEntry,
    handleError,
    logSecurityEvent,
    logAuthenticationAttempt,
    logAccessControlFailure,
    logValidationFailure,
    getLogs,
    getLogStatistics,
    cleanupOldLogs,
    errorHandlingMiddleware,
    requestLoggingMiddleware
};
