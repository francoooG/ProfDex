# ProfDex Setup Guide

## Quick Start

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Start the Application**
   ```bash
   npm start
   ```

3. **Access Your Application**
   - Main app: http://localhost:3000
   - Admin panel: http://localhost:3000/admin/login

## Automatic Admin Setup

✅ **No manual setup required!** The system automatically creates an administrator account on first startup.

**Default Admin Credentials:**
- **Email**: admin@profdex.com
- **Password**: admin123

**Important Security Note:** Change the password immediately after first login!

## What Happens on Startup

When you run `npm start`, the system will:

1. Connect to your MongoDB database
2. Check if an administrator account exists
3. If none exists, automatically create one with the default credentials
4. Start the web server
5. Display helpful console messages about the setup process

## Console Output Example

```
🔍 Checking for existing administrator account...
📝 No administrator found. Creating default admin account...
✅ Admin account created successfully!
   📧 Email: admin@profdex.com
   🔑 Password: admin123
   ⚠️  Remember to change the password after first login!
🚀 Server listening on port: 3000
📱 Access your application at: http://localhost:3000
🔐 Admin panel available at: http://localhost:3000/admin/login
```

## Troubleshooting

- **Database Connection Issues**: Check your `MONGODB_CONNECT_URI` environment variable
- **Port Already in Use**: Change the PORT variable in `index.js` or stop other services using port 3000
- **Admin Creation Fails**: Check the console for detailed error messages

## Next Steps

1. Login to the admin panel
2. Change the default password
3. Start managing users and roles
4. Explore the administrator dashboard features 