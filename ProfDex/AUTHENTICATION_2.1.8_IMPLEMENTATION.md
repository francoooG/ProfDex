# Authentication Requirement 2.1.8 Implementation: Account Lockout

## Overview
This document details the implementation of authentication requirement **2.1.8: Enforce account disabling after an established number of invalid login attempts**. The system now prevents brute force attacks by temporarily locking accounts after multiple failed login attempts while avoiding denial-of-service scenarios.

## Security Configuration

### Account Lockout Settings
The system uses configurable environment variables for account lockout behavior:

```javascript
const ACCOUNT_LOCKOUT_CONFIG = {
    MAX_FAILED_ATTEMPTS: parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5, // Default: 5 attempts
    LOCKOUT_DURATION_MINUTES: parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 15, // Default: 15 minutes
    RESET_ATTEMPTS_AFTER_MINUTES: parseInt(process.env.RESET_ATTEMPTS_AFTER_MINUTES) || 30, // Default: 30 minutes
    ENABLE_ACCOUNT_LOCKOUT: process.env.ENABLE_ACCOUNT_LOCKOUT !== 'false', // Default: true
    LOG_FAILED_ATTEMPTS: process.env.LOG_FAILED_ATTEMPTS !== 'false', // Default: true
    ADMIN_NOTIFICATION_THRESHOLD: parseInt(process.env.ADMIN_NOTIFICATION_THRESHOLD) || 10 // Default: 10 attempts
};
```

### Environment Variables
- `MAX_FAILED_ATTEMPTS`: Maximum failed attempts before lockout (default: 5)
- `LOCKOUT_DURATION_MINUTES`: Lockout duration in minutes (default: 15)
- `RESET_ATTEMPTS_AFTER_MINUTES`: Time to reset failed attempts (default: 30)
- `ENABLE_ACCOUNT_LOCKOUT`: Enable/disable account lockout (default: true)
- `LOG_FAILED_ATTEMPTS`: Enable/disable failed attempt logging (default: true)
- `ADMIN_NOTIFICATION_THRESHOLD`: Threshold for admin notifications (default: 10)

## Database Schema Changes

### User Schema Enhancements
Added account lockout fields to the User schema:

```javascript
// Account lockout fields
failedLoginAttempts: {
    type: Number,
    default: 0
},
accountLocked: {
    type: Boolean,
    default: false
},
lockoutExpiresAt: {
    type: Date,
    default: null
},
lastFailedLoginAt: {
    type: Date,
    default: null
}
```

## Core Functions

### 1. `checkAccountLockout(userId)`
Checks if an account is currently locked and handles lockout expiration.

**Features:**
- Validates lockout status against current time
- Automatically resets expired lockouts
- Resets failed attempts after configured time period
- Returns detailed lockout information including remaining time

**Return Value:**
```javascript
{
    isLocked: boolean,
    reason: string | null,
    remainingMinutes: number | null
}
```

### 2. `recordFailedLoginAttempt(userId, email)`
Records a failed login attempt and manages account locking.

**Features:**
- Increments failed attempt counter
- Logs failed attempts (configurable)
- Locks account when threshold is reached
- Sets lockout expiration time
- Sends admin notifications for high attempt counts

### 3. `resetAccountLockout(userId)`
Resets account lockout status after successful login.

**Features:**
- Clears failed attempt counter
- Unlocks account
- Removes lockout expiration
- Clears last failed login timestamp

### 4. `unlockAccount(userId)`
Manually unlocks an account (for administrative use).

**Features:**
- Removes account lock
- Clears lockout expiration
- Logs unlock action

## Authentication Flow Integration

### Login Process Enhancement
The `loginUser` function now includes account lockout checks:

1. **Pre-Authentication Check**: Verifies account lockout status before password verification
2. **Failed Attempt Recording**: Records failed attempts when password verification fails
3. **Successful Login Reset**: Resets lockout status on successful authentication

```javascript
// Check account lockout status before attempting authentication
const lockoutStatus = await checkAccountLockout(existingUser._id);
if (lockoutStatus.isLocked) {
    console.log(`Login attempt blocked for locked account: ${sanitizedEmail}`);
    return { error: 'account_locked', reason: lockoutStatus.reason };
}

// Record failed attempts on password mismatch
if (!passwordMatch) {
    await recordFailedLoginAttempt(existingUser._id, sanitizedEmail);
    return null;
}

// Reset lockout on successful login
await resetAccountLockout(existingUser._id);
```

## Route Handler Updates

### Login Route (`/login`)
Enhanced to handle account locked errors:

```javascript
// Check for account locked error
if (loggedInUser.error === 'account_locked') {
    res.redirect(`/login?error=account_locked&reason=${encodeURIComponent(loggedInUser.reason)}`);
    return;
}
```

### Admin Login Route (`/admin/login`)
Similar account locked error handling for administrator access.

## User Interface Updates

### Login Page (`LR_page.hbs`)
Added account locked error display:

```handlebars
{{#if errors.account_locked}}
    <b class="credentials-error">{{errors.account_locked_reason}}</b>
{{/if}}
```

### Admin Login Page (`admin_login.hbs`)
Added account locked error display for administrators.

## Security Benefits

### 1. **Brute Force Protection**
- Prevents automated password guessing attacks
- Configurable attempt limits prevent rapid-fire attacks
- Time-based lockouts discourage persistent attacks

### 2. **DoS Attack Prevention**
- Reasonable lockout durations (15 minutes default)
- Automatic lockout expiration
- Configurable reset periods (30 minutes default)

### 3. **Monitoring and Alerting**
- Failed attempt logging for security analysis
- Admin notifications for suspicious activity
- Detailed lockout reason messages

### 4. **User Experience**
- Clear error messages with remaining lockout time
- Automatic lockout expiration
- No manual intervention required for normal operation

## Configuration Options

### Production Recommendations
```bash
# Conservative settings for high-security environments
MAX_FAILED_ATTEMPTS=3
LOCKOUT_DURATION_MINUTES=30
RESET_ATTEMPTS_AFTER_MINUTES=60
ADMIN_NOTIFICATION_THRESHOLD=5

# Standard settings for most environments
MAX_FAILED_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15
RESET_ATTEMPTS_AFTER_MINUTES=30
ADMIN_NOTIFICATION_THRESHOLD=10

# Relaxed settings for user-friendly environments
MAX_FAILED_ATTEMPTS=10
LOCKOUT_DURATION_MINUTES=10
RESET_ATTEMPTS_AFTER_MINUTES=20
ADMIN_NOTIFICATION_THRESHOLD=15
```

## Testing Recommendations

### 1. **Account Lockout Testing**
- Test failed login attempts up to lockout threshold
- Verify lockout duration and expiration
- Test automatic reset after time period
- Verify successful login resets lockout

### 2. **Edge Case Testing**
- Test with disabled account lockout feature
- Verify behavior with invalid user accounts
- Test concurrent login attempts
- Verify admin notification thresholds

### 3. **Security Testing**
- Attempt brute force attacks against test accounts
- Verify lockout prevents further attempts
- Test timing attack prevention
- Verify error message security

## Compliance Verification

### ✅ **Requirement 2.1.8 Compliance**
- **Account Disabling**: ✅ Implemented with configurable attempt limits
- **Established Number**: ✅ Default 5 attempts, configurable via environment
- **Brute Force Prevention**: ✅ 15-minute lockout duration discourages attacks
- **DoS Prevention**: ✅ Reasonable timeouts and automatic expiration
- **User Notification**: ✅ Clear error messages with remaining time
- **Admin Monitoring**: ✅ Failed attempt logging and notifications

### **Security Controls**
- ✅ Configurable attempt limits
- ✅ Time-based lockout durations
- ✅ Automatic lockout expiration
- ✅ Failed attempt logging
- ✅ Admin notification system
- ✅ Clear user feedback
- ✅ Integration with existing authentication

## Files Modified

### Core Files
- `ProfDex/db/controller.js`: Account lockout functions and schema updates
- `ProfDex/index.js`: Route handler updates for account locked errors

### Template Files
- `ProfDex/views/LR_page.hbs`: Account locked error display
- `ProfDex/views/admin_login.hbs`: Admin account locked error display

### Documentation
- `ProfDex/AUTHENTICATION_2.1.8_IMPLEMENTATION.md`: This implementation guide

## Next Steps

The account lockout system is now fully implemented and integrated with the existing authentication system. The implementation provides robust protection against brute force attacks while maintaining system availability and user experience.

**Recommendations for deployment:**
1. Configure environment variables based on security requirements
2. Test account lockout behavior in staging environment
3. Monitor failed attempt logs in production
4. Consider implementing additional monitoring for suspicious patterns
5. Review and adjust lockout settings based on usage patterns
