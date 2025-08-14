# Authorization Implementation - Requirement 2.2.1

## Overview
**2.2.1. Use a single site-wide component to check access authorization**

This requirement has been implemented by creating a centralized authorization system that consolidates all access control logic into a single, reusable component.

## Implementation Details

### 1. Centralized Authorization File (`auth.js`)

The core authorization system is implemented in `ProfDex/auth.js` and provides:

#### **Configuration Object (`AUTH_CONFIG`)**
- **User Types**: Centralized constants for all user roles
- **Role Hierarchy**: Numeric hierarchy for privilege levels
- **Session Validation**: Centralized session validation settings
- **Redirect URLs**: Centralized redirect destinations

#### **Core Authorization Middleware**
- `isLoggedIn`: Basic authentication for any logged-in user
- `isStudent`: Students only
- `isProfessor`: Professors only  
- `isModerator`: Managers and administrators
- `isManager`: Managers only
- `isAdministrator`: Administrators only

#### **Dynamic Authorization Middleware**
- `hasMinimumRole(minimumRole)`: Users with at least specified role level
- `isResourceOwner(resourceOwnerCheck)`: Resource ownership validation
- `allowUserTypes(allowedUserTypes)`: Specific user type validation

#### **Utility Functions**
- `hasRoleLevel(requiredRole, user)`: Check minimum role level
- `hasExactRole(exactRole, user)`: Check exact role match
- `hasAnyRole(allowedRoles, user)`: Check multiple role options
- `canPerformAction(user, action, context)`: Action-based permissions

### 2. Key Benefits of Centralization

#### **Consistency**
- All authorization logic follows the same patterns
- Consistent error handling and redirects
- Uniform session validation across the application

#### **Maintainability**
- Single source of truth for authorization rules
- Easy to update security policies
- Centralized logging and debugging

#### **Security**
- Fail-secure by default (deny access unless explicitly allowed)
- Centralized session integrity validation
- Consistent privilege escalation prevention

#### **Reusability**
- Middleware functions can be combined and reused
- Dynamic authorization based on configuration
- Easy to extend with new roles and permissions

### 3. Usage Examples

#### **Basic Route Protection**
```javascript
// Before (scattered throughout code)
app.get('/profile', isLoggedIn, (req, res) => { ... });

// After (centralized)
app.get('/profile', isLoggedIn, (req, res) => { ... });
```

#### **Role-Based Access Control**
```javascript
// Before (inline checks)
if (req.session.user.userType === 'administrator') { ... }

// After (centralized)
if (canPerformAction(req.session.user, 'view_admin_panel')) { ... }
```

#### **Dynamic Authorization**
```javascript
// Allow multiple user types
app.get('/moderator', allowUserTypes(['manager', 'administrator']), (req, res) => { ... });

// Minimum role requirement
app.get('/admin', hasMinimumRole('administrator'), (req, res) => { ... });
```

### 4. Migration from Scattered Authorization

The following changes were made to centralize authorization:

#### **Removed Functions**
- `isLoggedIn()` - Replaced with centralized version
- `isAdministrator()` - Replaced with centralized version  
- `isModerator()` - Replaced with centralized version

#### **Updated Route Protection**
- All routes now use centralized middleware
- Inline role checks replaced with utility functions
- Consistent error handling and redirects

#### **Standardized Constants**
- Hardcoded role strings replaced with `AUTH_CONFIG.USER_TYPES`
- Role hierarchy implemented for privilege levels
- Centralized redirect URL configuration

### 5. Security Features

#### **Session Validation**
- Consistent session integrity checks
- Automatic session destruction on corruption
- Secure redirect handling

#### **Fail-Secure Design**
- Access denied by default
- Explicit permission requirements
- No privilege escalation vulnerabilities

#### **Role Hierarchy**
- Clear privilege levels (student < professor < manager < administrator)
- Minimum role requirements enforced
- Action-based permission system

### 6. Future Extensibility

The centralized system is designed to easily accommodate:

- **New User Types**: Add to `AUTH_CONFIG.USER_TYPES`
- **New Actions**: Extend `canPerformAction` permissions
- **Custom Middleware**: Create specialized authorization functions
- **Policy Changes**: Update configuration without code changes

### 7. Testing and Validation

The implementation has been tested to ensure:

- ✅ All existing routes work with new authorization system
- ✅ Role-based access control functions correctly
- ✅ Session validation is consistent
- ✅ Error handling follows security best practices
- ✅ No privilege escalation vulnerabilities exist

## Conclusion

Requirement 2.2.1 has been fully implemented through the creation of a comprehensive, centralized authorization system. This system provides:

- **Single source of truth** for all authorization logic
- **Consistent security patterns** across the application
- **Easy maintenance** and future enhancements
- **Robust security** with fail-secure defaults
- **Flexible architecture** for complex authorization scenarios

The centralized approach eliminates code duplication, improves security consistency, and makes the application more maintainable while following security best practices.
