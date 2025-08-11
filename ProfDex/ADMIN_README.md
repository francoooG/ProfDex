# ProfDex Administrator Features

This document describes the new administrator role and features implemented in ProfDex.

## Overview

The administrator role provides the highest level of system access and control, allowing system administrators to manage users, assign roles, and monitor system activity.

## Administrator Capabilities

### 1. User Management
- **View all users** in the system
- **Delete users** (with confirmation)
- **Assign/change user roles** (Student, Professor, Moderator, Administrator)

### 2. Role Assignment
- **Promote users to moderators** (Role A)
- **Demote users from moderators**
- **Change user types** between all available roles

### 3. System Access
- **Read-only access to application logs** (coming soon)
- **Full system overview** with user statistics
- **Secure admin-only routes**

## Setup Instructions

### 1. Administrator Account Setup

The administrator account is **automatically created** when you first start the application. No manual setup required!

Simply run:
```bash
npm start
```

The system will automatically create an administrator with:
- **Email**: admin@profdex.com
- **Password**: admin123

**Important**: Change the password after first login!

### 2. Access Administrator Panel

1. Navigate to `/admin/login` or click the "Admin" link in the main navigation
2. Login with administrator credentials
3. You'll be redirected to `/admin` dashboard

## Administrator Routes

### Protected Routes (Require Administrator Login)
- `/admin` - Main dashboard
- `/admin/users` - User management API
- `/admin/delete-user` - Delete user endpoint
- `/admin/update-role` - Update user role endpoint

### Public Routes
- `/admin/login` - Administrator login page

## User Role Hierarchy

1. **Administrator** (Highest)
   - Can manage all users
   - Can assign moderator roles
   - Can delete users
   - Can view system logs

2. **Moderator** (Role A)
   - Can assign users as professors or students
   - Can manage content within their scope

3. **Professor** (Role B)
   - Can view reviews
   - Can update profile
   - Can reply to reviews

4. **Student** (Role B)
   - Can create reviews
   - Can update profile
   - Can delete their own reviews

## Security Features

- **Role-based access control** (RBAC)
- **Session-based authentication**
- **Protected admin routes**
- **Confirmation dialogs** for destructive actions
- **Input validation** and sanitization

## Database Schema

### Administrator Collection
```javascript
{
  userId: ObjectId, // Reference to Users collection
  permissions: {
    canAssignModerators: Boolean,
    canDeleteUsers: Boolean,
    canManageRoles: Boolean,
    canViewLogs: Boolean
  }
}
```

### Updated User Schema
```javascript
{
  userType: {
    type: String,
    enum: ['student', 'professor', 'manager', 'administrator'],
    required: true
  }
  // ... other fields
}
```

## API Endpoints

### GET /admin
- **Purpose**: Load administrator dashboard
- **Access**: Administrator only
- **Response**: Renders admin dashboard with user data

### GET /admin/users
- **Purpose**: Get all users (JSON API)
- **Access**: Administrator only
- **Response**: Array of user objects

### POST /admin/delete-user
- **Purpose**: Delete a user
- **Access**: Administrator only
- **Body**: `{ userId: "user_id_here" }`
- **Response**: JSON success/error message

### POST /admin/update-role
- **Purpose**: Update user role
- **Access**: Administrator only
- **Body**: `{ userId: "user_id_here", newRole: "role_name" }`
- **Response**: JSON success/error message

## Frontend Features

### Admin Dashboard
- **System overview** with user statistics
- **Quick action buttons** for common tasks
- **User management table** with inline editing
- **Responsive design** for mobile and desktop

### User Management Table
- **Real-time role updates** via dropdown
- **Delete user buttons** with confirmation
- **Sortable columns** for better organization
- **Search and filter** capabilities (coming soon)

## Error Handling

- **Graceful error messages** for failed operations
- **User-friendly notifications** for successful actions
- **Input validation** with helpful error text
- **Fallback handling** for network issues

## Future Enhancements

- **System logs viewer** with filtering
- **Audit trail** for administrative actions
- **Bulk user operations** (import/export)
- **Advanced user search** and filtering
- **Role-based permission system** for administrators
- **Two-factor authentication** for admin accounts

## Troubleshooting

### Common Issues

1. **"Access denied" error**
   - Ensure you're logged in as an administrator
   - Check that your session is valid

2. **User role not updating**
   - Verify the user ID is correct
   - Check MongoDB connection
   - Ensure all required fields are present

3. **Dashboard not loading**
   - Check browser console for JavaScript errors
   - Verify all CSS files are loading
   - Check network tab for failed requests

### Debug Mode

Enable debug logging by setting environment variable:
```bash
DEBUG=profdex:admin npm start
```

## Support

For technical support or questions about administrator features, please refer to the main project documentation or contact the development team.

---

**Note**: This administrator system is designed with security in mind. Always use strong passwords and regularly review administrator access. 