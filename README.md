New files:


1. logger.js – central logger (console + daily-rotating files)

2. middleware/audit.js – tiny helpers to log auth attempts, validation failures, access denials

2. middleware/error.js – 404 + centralized error handler (no stack traces to users)


Minimal changes in index.js to:

  1. log auth attempts in /login

  2. log validation failures where you already validate

  3. log access-control denials in isLoggedIn, isAdministrator, isModerator

  4. admin-only logs can only be read by admins
