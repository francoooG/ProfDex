const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Password security configuration - Aligned with enterprise security policies
const PASSWORD_CONFIG = {
    SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 15, // Configurable salt rounds
    
    // Enhanced length requirements - Configurable via environment variables
    MIN_LENGTH: parseInt(process.env.PASSWORD_MIN_LENGTH) || 12, // Minimum length (configurable)
    MAX_LENGTH: parseInt(process.env.PASSWORD_MAX_LENGTH) || 128, // Maximum length (configurable)
    RECOMMENDED_MIN_LENGTH: parseInt(process.env.PASSWORD_RECOMMENDED_MIN_LENGTH) || 16, // Recommended minimum for better security
    STRONG_LENGTH_THRESHOLD: parseInt(process.env.PASSWORD_STRONG_LENGTH_THRESHOLD) || 20, // Length threshold for "strong" classification
    
    // Length-based complexity scoring
    LENGTH_COMPLEXITY_BONUS: true, // Enable length-based complexity scoring
    MIN_LENGTH_FOR_BONUS: 16, // Minimum length to receive complexity bonus
    BONUS_POINTS_PER_EXTRA_CHAR: 0.1, // Bonus points per character above minimum
    
    // Character type requirements
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SPECIAL_CHARS: true,
    PEPPER: process.env.PASSWORD_PEPPER || 'default-pepper-change-in-production', // Additional secret
    
    // Enhanced complexity requirements
    MIN_COMPLEXITY_SCORE: 3, // Minimum complexity score (0-4 scale)
    MAX_SEQUENTIAL_CHARS: 3, // Maximum consecutive sequential characters
    MAX_REPEATED_CHARS: 2, // Maximum consecutive repeated characters
    
    // Password history and age requirements
    PASSWORD_HISTORY_SIZE: 5, // Number of previous passwords to remember
    PASSWORD_MAX_AGE_DAYS: 90, // Maximum password age in days
    
    // Dictionary and pattern checks
    ENABLE_DICTIONARY_CHECK: true,
    ENABLE_KEYBOARD_PATTERN_CHECK: true,
    ENABLE_SEQUENTIAL_CHECK: true,
    
    // Length-based security features
    ENABLE_LENGTH_HISTORY_CHECK: true, // Check for length-based patterns in password history
    MIN_LENGTH_VARIATION: 2, // Minimum variation in password lengths to prevent patterns
    MAX_LENGTH_VARIATION: 10 // Maximum variation in password lengths to prevent predictable patterns
};

// Account lockout configuration - Prevents brute force attacks while avoiding DoS
const ACCOUNT_LOCKOUT_CONFIG = {
    MAX_FAILED_ATTEMPTS: parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5, // Maximum failed attempts before lockout
    LOCKOUT_DURATION_MINUTES: parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 15, // Lockout duration in minutes
    RESET_ATTEMPTS_AFTER_MINUTES: parseInt(process.env.RESET_ATTEMPTS_AFTER_MINUTES) || 30, // Reset failed attempts after this time
    ENABLE_ACCOUNT_LOCKOUT: process.env.ENABLE_ACCOUNT_LOCKOUT !== 'false', // Default to true
    LOG_FAILED_ATTEMPTS: process.env.LOG_FAILED_ATTEMPTS !== 'false', // Default to true
    ADMIN_NOTIFICATION_THRESHOLD: parseInt(process.env.ADMIN_NOTIFICATION_THRESHOLD) || 10 // Notify admin after this many failed attempts
};

// Password reset configuration - Secure password reset with random questions
const PASSWORD_RESET_CONFIG = {
    RESET_TOKEN_EXPIRY_HOURS: parseInt(process.env.RESET_TOKEN_EXPIRY_HOURS) || 24, // Token expiry time
    MAX_RESET_ATTEMPTS: parseInt(process.env.MAX_RESET_ATTEMPTS) || 3, // Maximum reset attempts per day
    RESET_ATTEMPTS_WINDOW_HOURS: parseInt(process.env.RESET_ATTEMPTS_WINDOW_HOURS) || 24, // Window for counting attempts
    ENABLE_SECURITY_QUESTIONS: process.env.ENABLE_SECURITY_QUESTIONS !== 'false', // Default to true
    MIN_ANSWER_LENGTH: parseInt(process.env.MIN_ANSWER_LENGTH) || 3, // Minimum answer length
    MAX_ANSWER_LENGTH: parseInt(process.env.MAX_ANSWER_LENGTH) || 100, // Maximum answer length
    REQUIRE_ANSWER_COMPLEXITY: process.env.REQUIRE_ANSWER_COMPLEXITY !== 'false', // Default to true
    MIN_ANSWER_COMPLEXITY_SCORE: parseInt(process.env.MIN_ANSWER_COMPLEXITY_SCORE) || 1 // Reduced minimum complexity score for answers
};

// Security questions configuration - Questions that support sufficiently random answers
const SECURITY_QUESTIONS = [
    {
        id: 'q1',
        question: 'What was the name of your first pet?',
        category: 'personal',
        difficulty: 'medium',
        commonAnswers: ['dog', 'cat', 'fish', 'bird', 'hamster', 'rabbit']
    },
    {
        id: 'q2',
        question: 'What was the street name of your childhood home?',
        category: 'personal',
        difficulty: 'high',
        commonAnswers: ['main', 'oak', 'maple', 'pine', 'elm', 'cedar']
    },
    {
        id: 'q3',
        question: 'What was your favorite subject in high school?',
        category: 'personal',
        difficulty: 'medium',
        commonAnswers: ['math', 'science', 'english', 'history', 'art', 'music']
    },
    {
        id: 'q4',
        question: 'What was the model of your first car?',
        category: 'personal',
        difficulty: 'high',
        commonAnswers: ['toyota', 'honda', 'ford', 'chevrolet', 'nissan', 'bmw']
    },
    {
        id: 'q5',
        question: 'What was the name of your first employer?',
        category: 'professional',
        difficulty: 'high',
        commonAnswers: ['mcdonalds', 'walmart', 'target', 'starbucks', 'subway']
    },
    {
        id: 'q6',
        question: 'What was the color of your first bicycle?',
        category: 'personal',
        difficulty: 'medium',
        commonAnswers: ['red', 'blue', 'green', 'black', 'white', 'yellow']
    },
    {
        id: 'q7',
        question: 'What was the name of your childhood best friend?',
        category: 'personal',
        difficulty: 'high',
        commonAnswers: ['john', 'mike', 'sarah', 'jessica', 'david', 'emma']
    },
    {
        id: 'q8',
        question: 'What was the first concert you attended?',
        category: 'personal',
        difficulty: 'high',
        commonAnswers: ['concert', 'show', 'performance']
    },
    {
        id: 'q9',
        question: 'What was the name of your first teacher?',
        category: 'personal',
        difficulty: 'high',
        commonAnswers: ['mrs', 'mr', 'ms', 'dr', 'professor']
    },
    {
        id: 'q10',
        question: 'What was the make and model of your first computer?',
        category: 'technical',
        difficulty: 'high',
        commonAnswers: ['dell', 'hp', 'apple', 'lenovo', 'acer', 'asus']
    }
];

// Security question answer validation function
function validateSecurityAnswer(answer, questionId) {
    const errors = [];
    let complexityScore = 0;
    
    if (!answer || typeof answer !== 'string') {
        errors.push('Answer must be a valid string');
        return { isValid: false, errors, complexityScore: 0 };
    }
    
    // Length validation
    if (answer.length < PASSWORD_RESET_CONFIG.MIN_ANSWER_LENGTH) {
        errors.push(`Answer must be at least ${PASSWORD_RESET_CONFIG.MIN_ANSWER_LENGTH} characters long`);
    }
    
    if (answer.length > PASSWORD_RESET_CONFIG.MAX_ANSWER_LENGTH) {
        errors.push(`Answer must be no more than ${PASSWORD_RESET_CONFIG.MAX_ANSWER_LENGTH} characters long`);
    }
    
    // Find the question to check against common answers
    const question = SECURITY_QUESTIONS.find(q => q.id === questionId);
    if (!question) {
        errors.push('Invalid security question');
        return { isValid: false, errors, complexityScore: 0 };
    }
    
    // Check against common answers (case-insensitive) - only exact matches
    const normalizedAnswer = answer.toLowerCase().trim();
    if (question.commonAnswers.some(common => normalizedAnswer === common.toLowerCase())) {
        errors.push('Answer is too common. Please provide a more specific or unique answer.');
    }
    
    // Complexity scoring if enabled
    if (PASSWORD_RESET_CONFIG.REQUIRE_ANSWER_COMPLEXITY) {
        // Check for mixed case
        if (/[a-z]/.test(answer) && /[A-Z]/.test(answer)) {
            complexityScore += 1;
        }
        
        // Check for numbers
        if (/\d/.test(answer)) {
            complexityScore += 1;
        }
        
        // Check for special characters
        if (/[^a-zA-Z0-9\s]/.test(answer)) {
            complexityScore += 1;
        }
        
        // Check for length bonus (reduced threshold for security answers)
        if (answer.length >= 6) {
            complexityScore += 1;
        }
        
        // Check for multiple words (more lenient for security answers)
        const words = answer.toLowerCase().split(/\s+/);
        const uniqueWords = new Set(words);
        if (uniqueWords.size >= 2) {
            complexityScore += 1;
        }
        
        // Bonus for longer answers (more lenient scoring)
        if (answer.length >= 10) {
            complexityScore += 1;
        }
        
        // Bonus for answers with spaces (indicates more specific answers)
        if (answer.includes(' ')) {
            complexityScore += 1;
        }
        
        if (complexityScore < PASSWORD_RESET_CONFIG.MIN_ANSWER_COMPLEXITY_SCORE) {
            errors.push(`Answer complexity is too low. Please provide a more complex answer (minimum score: ${PASSWORD_RESET_CONFIG.MIN_ANSWER_COMPLEXITY_SCORE})`);
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors,
        complexityScore,
        answerLength: answer.length
    };
}

// Enhanced password strength validation function with enterprise-grade complexity requirements
function validatePasswordStrength(password) {
    const errors = [];
    let complexityScore = 0;
    let lengthScore = 0;
    
    if (!password || typeof password !== 'string') {
        errors.push('Password must be a valid string');
        return { isValid: false, errors, complexityScore: 0, lengthScore: 0 };
    }
    
    // Enhanced length requirements with detailed feedback
    if (password.length < PASSWORD_CONFIG.MIN_LENGTH) {
        errors.push(`Password must be at least ${PASSWORD_CONFIG.MIN_LENGTH} characters long (current: ${password.length})`);
    }
    
    if (password.length > PASSWORD_CONFIG.MAX_LENGTH) {
        errors.push(`Password must be no more than ${PASSWORD_CONFIG.MAX_LENGTH} characters long (current: ${password.length})`);
    }
    
    // Length-based scoring and recommendations
    if (password.length >= PASSWORD_CONFIG.MIN_LENGTH) {
        lengthScore = 1; // Base score for meeting minimum
        
        if (password.length >= PASSWORD_CONFIG.RECOMMENDED_MIN_LENGTH) {
            lengthScore = 2; // Bonus for meeting recommended length
        }
        
        if (password.length >= PASSWORD_CONFIG.STRONG_LENGTH_THRESHOLD) {
            lengthScore = 3; // Bonus for meeting strong length threshold
        }
        
        // Length-based complexity bonus
        if (PASSWORD_CONFIG.LENGTH_COMPLEXITY_BONUS && password.length >= PASSWORD_CONFIG.MIN_LENGTH_FOR_BONUS) {
            const extraChars = password.length - PASSWORD_CONFIG.MIN_LENGTH_FOR_BONUS;
            const bonusPoints = extraChars * PASSWORD_CONFIG.BONUS_POINTS_PER_EXTRA_CHAR;
            lengthScore += bonusPoints;
        }
    }
    
    // Length-based warnings (not errors, but recommendations)
    const warnings = [];
    if (password.length >= PASSWORD_CONFIG.MIN_LENGTH && password.length < PASSWORD_CONFIG.RECOMMENDED_MIN_LENGTH) {
        warnings.push(`Consider using at least ${PASSWORD_CONFIG.RECOMMENDED_MIN_LENGTH} characters for better security`);
    }
    
    // Character type requirements
    if (PASSWORD_CONFIG.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    } else if (/[A-Z]/.test(password)) {
        complexityScore++;
    }
    
    if (PASSWORD_CONFIG.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    } else if (/[a-z]/.test(password)) {
        complexityScore++;
    }
    
    if (PASSWORD_CONFIG.REQUIRE_NUMBERS && !/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    } else if (/\d/.test(password)) {
        complexityScore++;
    }
    
    if (PASSWORD_CONFIG.REQUIRE_SPECIAL_CHARS && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        errors.push('Password must contain at least one special character');
    } else if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        complexityScore++;
    }
    
    // Enhanced complexity scoring
    if (complexityScore < PASSWORD_CONFIG.MIN_COMPLEXITY_SCORE) {
        errors.push(`Password complexity is too low. Must meet at least ${PASSWORD_CONFIG.MIN_COMPLEXITY_SCORE} complexity criteria`);
    }
    
    // Sequential character checks
    if (PASSWORD_CONFIG.ENABLE_SEQUENTIAL_CHECK) {
        const sequentialPatterns = [
            '123', '234', '345', '456', '789', '012',
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
            'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop', 'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl', 'zxc', 'xcv', 'cvb', 'vbn', 'bnm'
        ];
        
        for (const pattern of sequentialPatterns) {
            if (password.toLowerCase().includes(pattern)) {
                errors.push('Password contains sequential characters which are easily guessable');
                break;
            }
        }
    }
    
    // Repeated character checks
    if (PASSWORD_CONFIG.MAX_REPEATED_CHARS > 0) {
        for (let i = 0; i < password.length - PASSWORD_CONFIG.MAX_REPEATED_CHARS; i++) {
            const char = password[i];
            let repeated = 1;
            for (let j = i + 1; j < password.length; j++) {
                if (password[j] === char) {
                    repeated++;
                } else {
                    break;
                }
            }
            if (repeated > PASSWORD_CONFIG.MAX_REPEATED_CHARS) {
                errors.push(`Password contains too many consecutive repeated characters (${repeated} '${char}' in a row)`);
                break;
            }
        }
    }
    
    // Keyboard pattern checks
    if (PASSWORD_CONFIG.ENABLE_KEYBOARD_PATTERN_CHECK) {
        const keyboardPatterns = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', '654321',
            'qazwsx', 'edcrfv', 'tgbyhn', 'ujmikl', 'plokij'
        ];
        
        for (const pattern of keyboardPatterns) {
            if (password.toLowerCase().includes(pattern)) {
                errors.push('Password contains keyboard patterns which are easily guessable');
                break;
            }
        }
    }
    
    // Dictionary and common password checks
    if (PASSWORD_CONFIG.ENABLE_DICTIONARY_CHECK) {
        const commonPasswords = [
            'password', '123456', 'password123', 'admin', 'user', 'test',
            'welcome', 'monkey', 'dragon', 'master', 'letmein', 'login',
            'abc123', 'qwerty', 'football', 'baseball', 'superman', 'batman',
            'trustno1', 'shadow', 'michael', 'jordan', 'harley', 'ranger',
            'buster', 'thomas', 'tigger', 'robert', 'soccer', 'batman',
            'test123', 'guest', 'info', 'adm', 'mysql', 'user1', 'administrator'
        ];
        
        if (commonPasswords.includes(password.toLowerCase())) {
            errors.push('Password is too common and easily guessable');
        }
        
        // Check for common words with simple substitutions
        const commonWords = ['password', 'admin', 'user', 'test', 'welcome', 'login'];
        for (const word of commonWords) {
            const substitutions = {
                'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['$', '5'], 't': ['7']
            };
            
            let modifiedWord = word;
            for (const [letter, replacements] of Object.entries(substitutions)) {
                for (const replacement of replacements) {
                    modifiedWord = modifiedWord.replace(new RegExp(letter, 'g'), replacement);
                }
            }
            
            if (password.toLowerCase().includes(modifiedWord)) {
                errors.push('Password contains common words with simple character substitutions');
                break;
            }
        }
    }
    
    // Calculate total score including length bonus
    const totalScore = complexityScore + lengthScore;
    
    return {
        isValid: errors.length === 0,
        errors,
        warnings,
        complexityScore,
        lengthScore,
        totalScore,
        passwordLength: password.length,
        lengthClassification: getLengthClassification(password.length)
    };
}

// Get length classification for password strength assessment
function getLengthClassification(length) {
    if (length < PASSWORD_CONFIG.MIN_LENGTH) {
        return 'too_short';
    } else if (length < PASSWORD_CONFIG.RECOMMENDED_MIN_LENGTH) {
        return 'minimum';
    } else if (length < PASSWORD_CONFIG.STRONG_LENGTH_THRESHOLD) {
        return 'recommended';
    } else {
        return 'strong';
    }
}

// Check if password has been used recently (password history validation)
async function checkPasswordHistory(userId, newPassword) {
    try {
        // Get recent password history
        const passwordHistory = await PasswordHistory.find({ userId })
            .sort({ createdAt: -1 })
            .limit(PASSWORD_CONFIG.PASSWORD_HISTORY_SIZE);
        
        // Check if new password matches any recent password
        for (const historyEntry of passwordHistory) {
            const isMatch = await verifyPassword(newPassword, historyEntry.hashedPassword);
            if (isMatch) {
                return {
                    isValid: false,
                    error: `Password has been used recently. Please choose a different password.`
                };
            }
        }
        
        return { isValid: true };
    } catch (error) {
        console.error('Error checking password history:', error);
        // Fail securely - if we can't check history, allow the password change
        return { isValid: true };
    }
}

// Check if password has expired (password age validation)
async function checkPasswordAge(userId) {
    try {
        const user = await User.findById(userId);
        if (!user || !user.passwordChangedAt) {
            return { isExpired: false };
        }
        
        const passwordAge = Date.now() - user.passwordChangedAt.getTime();
        const maxAgeMs = PASSWORD_CONFIG.PASSWORD_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
        
        return {
            isExpired: passwordAge > maxAgeMs,
            daysRemaining: Math.ceil((maxAgeMs - passwordAge) / (24 * 60 * 60 * 1000))
        };
    } catch (error) {
        console.error('Error checking password age:', error);
        // Fail securely - if we can't check age, assume not expired
        return { isExpired: false };
    }
}

// Check for length-based patterns in password history
async function checkLengthPatterns(userId, newPasswordLength) {
    try {
        if (!PASSWORD_CONFIG.ENABLE_LENGTH_HISTORY_CHECK) {
            return { isValid: true };
        }
        
        // Get recent password history lengths
        const passwordHistory = await PasswordHistory.find({ userId })
            .sort({ createdAt: -1 })
            .limit(PASSWORD_CONFIG.PASSWORD_HISTORY_SIZE);
        
        if (passwordHistory.length === 0) {
            return { isValid: true };
        }
        
        // Check for length patterns
        const lengths = passwordHistory.map(entry => entry.hashedPassword.length); // Note: we can't get actual length from hash
        const avgLength = lengths.reduce((sum, len) => sum + len, 0) / lengths.length;
        const lengthVariation = Math.abs(newPasswordLength - avgLength);
        
        // Check if length variation is within acceptable range
        if (lengthVariation < PASSWORD_CONFIG.MIN_LENGTH_VARIATION) {
            return {
                isValid: false,
                error: 'Password length is too similar to previous passwords. Please choose a different length.'
            };
        }
        
        if (lengthVariation > PASSWORD_CONFIG.MAX_LENGTH_VARIATION) {
            return {
                isValid: false,
                error: 'Password length variation is too extreme. Please choose a more reasonable length.'
            };
        }
        
        return { isValid: true };
    } catch (error) {
        console.error('Error checking length patterns:', error);
        // Fail securely - if we can't check patterns, allow the password
        return { isValid: true };
    }
}

// Add password to history
async function addPasswordToHistory(userId, hashedPassword) {
    try {
        const passwordHistoryEntry = new PasswordHistory({
            userId: userId,
            hashedPassword: hashedPassword
        });
        await passwordHistoryEntry.save();
        
        // Clean up old entries beyond the history size
        const allHistory = await PasswordHistory.find({ userId }).sort({ createdAt: -1 });
        if (allHistory.length > PASSWORD_CONFIG.PASSWORD_HISTORY_SIZE) {
            const entriesToDelete = allHistory.slice(PASSWORD_CONFIG.PASSWORD_HISTORY_SIZE);
            await PasswordHistory.deleteMany({ _id: { $in: entriesToDelete.map(entry => entry._id) } });
        }
    } catch (error) {
        console.error('Error adding password to history:', error);
        // Don't fail the password change if history tracking fails
    }
}

// Enhanced password hashing function with pepper
async function hashPassword(password) {
    try {
        // Add pepper to password before hashing
        const pepperedPassword = password + PASSWORD_CONFIG.PEPPER;
        
        // Generate cryptographically strong salted hash
        const hashedPassword = await bcrypt.hash(pepperedPassword, PASSWORD_CONFIG.SALT_ROUNDS);
        
        console.log(`Password hashed successfully with ${PASSWORD_CONFIG.SALT_ROUNDS} salt rounds`);
        return hashedPassword;
    } catch (error) {
        console.error('Error hashing password:', error);
        throw new Error('Password hashing failed');
    }
}

// Enhanced password verification function
async function verifyPassword(password, hashedPassword) {
    try {
        // Add pepper to password before comparison
        const pepperedPassword = password + PASSWORD_CONFIG.PEPPER;
        
        // Use constant-time comparison to prevent timing attacks
        const isValid = await bcrypt.compare(pepperedPassword, hashedPassword);
        return isValid;
    } catch (error) {
        console.error('Error verifying password:', error);
        return false;
    }
}

// Account lockout management functions
async function checkAccountLockout(userId) {
    try {
        if (!ACCOUNT_LOCKOUT_CONFIG.ENABLE_ACCOUNT_LOCKOUT) {
            return { isLocked: false, reason: null };
        }

        const user = await User.findById(userId);
        if (!user) {
            return { isLocked: false, reason: null };
        }

        // Check if account is currently locked
        if (user.accountLocked && user.lockoutExpiresAt) {
            const now = new Date();
            if (now < user.lockoutExpiresAt) {
                const remainingMinutes = Math.ceil((user.lockoutExpiresAt - now) / (1000 * 60));
                return { 
                    isLocked: true, 
                    reason: `Account is locked due to too many failed login attempts. Try again in ${remainingMinutes} minutes.`,
                    remainingMinutes
                };
            } else {
                // Lockout has expired, reset the account
                await resetAccountLockout(userId);
                return { isLocked: false, reason: null };
            }
        }

        // Check if failed attempts should be reset due to time
        if (user.lastFailedLoginAt) {
            const now = new Date();
            const timeSinceLastAttempt = (now - user.lastFailedLoginAt) / (1000 * 60); // minutes
            
            if (timeSinceLastAttempt >= ACCOUNT_LOCKOUT_CONFIG.RESET_ATTEMPTS_AFTER_MINUTES) {
                await resetAccountLockout(userId);
                return { isLocked: false, reason: null };
            }
        }

        return { isLocked: false, reason: null };
    } catch (error) {
        console.error('Error checking account lockout:', error);
        return { isLocked: false, reason: null }; // Fail open for availability
    }
}

async function recordFailedLoginAttempt(userId, email) {
    try {
        if (!ACCOUNT_LOCKOUT_CONFIG.ENABLE_ACCOUNT_LOCKOUT) {
            return;
        }

        const user = await User.findById(userId);
        if (!user) {
            return;
        }

        const now = new Date();
        const newFailedAttempts = user.failedLoginAttempts + 1;

        // Log failed attempt if enabled
        if (ACCOUNT_LOCKOUT_CONFIG.LOG_FAILED_ATTEMPTS) {
            console.log(`Failed login attempt ${newFailedAttempts} for user: ${email}`);
        }

        // Check if account should be locked
        if (newFailedAttempts >= ACCOUNT_LOCKOUT_CONFIG.MAX_FAILED_ATTEMPTS) {
            const lockoutExpiresAt = new Date(now.getTime() + (ACCOUNT_LOCKOUT_CONFIG.LOCKOUT_DURATION_MINUTES * 60 * 1000));
            
            await User.findByIdAndUpdate(userId, {
                failedLoginAttempts: newFailedAttempts,
                accountLocked: true,
                lockoutExpiresAt: lockoutExpiresAt,
                lastFailedLoginAt: now
            });

            console.log(`Account locked for user: ${email} due to ${newFailedAttempts} failed attempts. Lockout expires at: ${lockoutExpiresAt}`);

            // Notify admin if threshold is reached
            if (newFailedAttempts >= ACCOUNT_LOCKOUT_CONFIG.ADMIN_NOTIFICATION_THRESHOLD) {
                console.log(`ADMIN ALERT: User ${email} has ${newFailedAttempts} failed login attempts`);
            }
        } else {
            // Just update the failed attempts count
            await User.findByIdAndUpdate(userId, {
                failedLoginAttempts: newFailedAttempts,
                lastFailedLoginAt: now
            });
        }
    } catch (error) {
        console.error('Error recording failed login attempt:', error);
    }
}

async function resetAccountLockout(userId) {
    try {
        await User.findByIdAndUpdate(userId, {
            failedLoginAttempts: 0,
            accountLocked: false,
            lockoutExpiresAt: null,
            lastFailedLoginAt: null
        });
    } catch (error) {
        console.error('Error resetting account lockout:', error);
    }
}

async function unlockAccount(userId) {
    try {
        await User.findByIdAndUpdate(userId, {
            accountLocked: false,
            lockoutExpiresAt: null
        });
        console.log(`Account unlocked for user ID: ${userId}`);
    } catch (error) {
        console.error('Error unlocking account:', error);
    }
}

// Password reset functions
async function generatePasswordResetToken(email) {
    try {
        // Find user by email
        const user = await User.findOne({ email: email.toLowerCase().trim() });
        if (!user) {
            return { success: false, error: 'User not found' };
        }
        
        // Check if user has security questions set up
        const securityQuestions = await SecurityQuestions.findOne({ userId: user._id });
        if (!securityQuestions) {
            return { success: false, error: 'Security questions not configured' };
        }
        
        // Check reset attempts limit
        const recentAttempts = await PasswordResetToken.countDocuments({
            userId: user._id,
            createdAt: { 
                $gte: new Date(Date.now() - PASSWORD_RESET_CONFIG.RESET_ATTEMPTS_WINDOW_HOURS * 60 * 60 * 1000) 
            }
        });
        
        if (recentAttempts >= PASSWORD_RESET_CONFIG.MAX_RESET_ATTEMPTS) {
            return { success: false, error: 'Too many reset attempts. Please try again later.' };
        }
        
        // Generate secure token
        const crypto = require('crypto');
        const token = crypto.randomBytes(32).toString('hex');
        
        // Set expiry time
        const expiresAt = new Date(Date.now() + PASSWORD_RESET_CONFIG.RESET_TOKEN_EXPIRY_HOURS * 60 * 60 * 1000);
        
        // Save token
        await PasswordResetToken.create({
            userId: user._id,
            token: token,
            expiresAt: expiresAt
        });
        
        return { 
            success: true, 
            token: token,
            userId: user._id,
            email: user.email
        };
    } catch (error) {
        console.error('Error generating password reset token:', error);
        return { success: false, error: 'Failed to generate reset token' };
    }
}

async function validatePasswordResetToken(token) {
    try {
        const resetToken = await PasswordResetToken.findOne({
            token: token,
            used: false,
            expiresAt: { $gt: new Date() }
        });
        
        if (!resetToken) {
            return { success: false, error: 'Invalid or expired token' };
        }
        
        return { success: true, userId: resetToken.userId };
    } catch (error) {
        console.error('Error validating password reset token:', error);
        return { success: false, error: 'Failed to validate token' };
    }
}

async function verifySecurityQuestions(userId, answers) {
    try {
        const securityQuestions = await SecurityQuestions.findOne({ userId: userId });
        if (!securityQuestions) {
            return { success: false, error: 'Security questions not found' };
        }
        
        // Verify each answer using hash comparison
        const questions = [securityQuestions.question1, securityQuestions.question2, securityQuestions.question3];
        const providedAnswers = [answers.answer1, answers.answer2, answers.answer3];
        
        for (let i = 0; i < questions.length; i++) {
            const hashedExpectedAnswer = questions[i].answer;
            const providedAnswer = providedAnswers[i];
            
            // Use verifyPassword function to compare (since answers are hashed with the same method)
            const isCorrect = await verifyPassword(providedAnswer, hashedExpectedAnswer);
            
            if (!isCorrect) {
                return { success: false, error: 'One or more security answers are incorrect' };
            }
        }
        
        return { success: true };
    } catch (error) {
        console.error('Error verifying security questions:', error);
        return { success: false, error: 'Failed to verify security questions' };
    }
}

async function resetPasswordWithToken(token, newPassword) {
    try {
        // Validate token
        const tokenValidation = await validatePasswordResetToken(token);
        if (!tokenValidation.success) {
            return tokenValidation;
        }
        
        // Validate new password
        const passwordValidation = validatePasswordStrength(newPassword);
        if (!passwordValidation.isValid) {
            return { 
                success: false, 
                error: 'password_validation', 
                details: passwordValidation.errors 
            };
        }
        
        // Hash new password
        const hashedPassword = await hashPassword(newPassword);
        
        // Update user password
        await User.findByIdAndUpdate(tokenValidation.userId, {
            password: hashedPassword,
            passwordChangedAt: new Date()
        });
        
        // Mark token as used
        await PasswordResetToken.findOneAndUpdate(
            { token: token },
            { used: true }
        );
        
        // Add to password history
        await addPasswordToHistory(tokenValidation.userId, hashedPassword);
        
        return { success: true };
    } catch (error) {
        console.error('Error resetting password:', error);
        return { success: false, error: 'Failed to reset password' };
    }
}

async function setupSecurityQuestions(userId, questions) {
    try {
        console.log('Setting up security questions for user:', userId);
        console.log('Questions received:', questions);
        
        // Validate each answer
        const questionsToValidate = [
            { answer: questions.answer1, questionId: questions.question1 },
            { answer: questions.answer2, questionId: questions.question2 },
            { answer: questions.answer3, questionId: questions.question3 }
        ];
        
        for (const q of questionsToValidate) {
            console.log('Validating question:', q.questionId, 'with answer:', q.answer);
            const validation = validateSecurityAnswer(q.answer, q.questionId);
            if (!validation.isValid) {
                console.log('Validation failed for question:', q.questionId, 'Errors:', validation.errors);
                return { 
                    success: false, 
                    error: 'security_question_validation', 
                    details: validation.errors 
                };
            }
        }
        
        console.log('All answers validated successfully');
        
        // Hash answers before storing
        const hashedAnswers = {
            question1: {
                questionId: questions.question1,
                answer: await hashPassword(questions.answer1)
            },
            question2: {
                questionId: questions.question2,
                answer: await hashPassword(questions.answer2)
            },
            question3: {
                questionId: questions.question3,
                answer: await hashPassword(questions.answer3)
            }
        };
        
        console.log('Answers hashed successfully');
        
        // Save or update security questions
        const result = await SecurityQuestions.findOneAndUpdate(
            { userId: userId },
            hashedAnswers,
            { upsert: true, new: true }
        );
        
        console.log('Security questions saved to database:', result ? 'Success' : 'Failed');
        
        return { success: true };
    } catch (error) {
        console.error('Error setting up security questions:', error);
        return { success: false, error: 'Failed to setup security questions' };
    }
}

async function getSecurityQuestions(userId) {
    try {
        const securityQuestions = await SecurityQuestions.findOne({ userId: userId });
        if (!securityQuestions) {
            return { success: false, error: 'Security questions not found' };
        }
        
        // Return questions without answers for security
        return {
            success: true,
            questions: [
                {
                    questionId: securityQuestions.question1.questionId,
                    question: SECURITY_QUESTIONS.find(q => q.id === securityQuestions.question1.questionId)?.question
                },
                {
                    questionId: securityQuestions.question2.questionId,
                    question: SECURITY_QUESTIONS.find(q => q.id === securityQuestions.question2.questionId)?.question
                },
                {
                    questionId: securityQuestions.question3.questionId,
                    question: SECURITY_QUESTIONS.find(q => q.id === securityQuestions.question3.questionId)?.question
                }
            ]
        };
    } catch (error) {
        console.error('Error getting security questions:', error);
        return { success: false, error: 'Failed to get security questions' };
    }
}

async function cleanupExpiredTokens() {
    try {
        const result = await PasswordResetToken.deleteMany({
            expiresAt: { $lt: new Date() }
        });
        console.log(`Cleaned up ${result.deletedCount} expired password reset tokens`);
    } catch (error) {
        console.error('Error cleaning up expired tokens:', error);
    }
}

var Schema = mongoose.Schema;

// Password reset token schema
var passwordResetTokenSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    expiresAt: {
        type: Date,
        required: true
    },
    used: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Security questions schema
var securityQuestionsSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    question1: {
        questionId: {
            type: String,
            required: true
        },
        answer: {
            type: String,
            required: true
        }
    },
    question2: {
        questionId: {
            type: String,
            required: true
        },
        answer: {
            type: String,
            required: true
        }
    },
    question3: {
        questionId: {
            type: String,
            required: true
        },
        answer: {
            type: String,
            required: true
        }
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Password reset attempts schema
var passwordResetAttemptSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    attempts: {
        type: Number,
        default: 0
    },
    lastAttempt: {
        type: Date,
        default: Date.now
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

var userSchema = new Schema({
    firstName: {
        type: String,
        required: true
    },
    lastName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    userType: {
        type: String,
        enum: ['student', 'professor', 'manager', 'administrator'],
        required: true
    },
    passwordChangedAt: {
        type: Date,
        default: Date.now
    },
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
});
var User = mongoose.model("Users", userSchema);
var PasswordResetToken = mongoose.model("PasswordResetTokens", passwordResetTokenSchema);
var SecurityQuestions = mongoose.model("SecurityQuestions", securityQuestionsSchema);
var PasswordResetAttempt = mongoose.model("PasswordResetAttempts", passwordResetAttemptSchema);

var studentSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    studentID: {
        type: String,
        required: true,
        unique: true
    },
    bio: {
        type: String,
        default: ''
    },
    course: {
        type: Schema.Types.ObjectId,
        ref: 'Courses',
        required: true
    }
});
var Student = mongoose.model("Students", studentSchema);

var professorSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    teacherID: {
        type: String,
        required: true,
        unique: true
    },
    bio: {
        type: String,
        default: ''
    },
    subjects: [{
        type: Schema.Types.ObjectId,
        ref: 'Subjects'
    }]
});
var Professor = mongoose.model("Professors", professorSchema);

var courseSchema = new Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    code: {
        type: String,
        required: true,
        unique: true
    },
    description: {
        type: String,
        default: ''
    }
});
var Course = mongoose.model("Courses", courseSchema);

var subjectSchema = new Schema({
    name: {
        type: String,
        required: true,
        unique: true
    },
    code: {
        type: String,
        required: true,
        unique: true
    },
    description: {
        type: String,
        default: ''
    }
});
var Subject = mongoose.model("Subjects", subjectSchema);

var managerSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    }
});
var Manager = mongoose.model("Managers", managerSchema);

var administratorSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    permissions: {
        canAssignModerators: { type: Boolean, default: true },
        canDeleteUsers: { type: Boolean, default: true },
        canManageRoles: { type: Boolean, default: true },
        canViewLogs: { type: Boolean, default: true }
    }
});
var Administrator = mongoose.model("Administrators", administratorSchema);

// Password history schema for tracking previous passwords
var passwordHistorySchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    hashedPassword: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: PASSWORD_CONFIG.PASSWORD_MAX_AGE_DAYS * 24 * 60 * 60 // Auto-delete after max age
    }
});
var PasswordHistory = mongoose.model("PasswordHistory", passwordHistorySchema);

var postSchema = new Schema({
    aPost: {
        type: Object,
        text: String
    },
    op: String,
    to: { type: Schema.Types.ObjectId, ref: 'Professors' },
    course: String,
    opname: String,
    toname: String,
    difficulty: Number,
    engagement: Number,
    generosity: Number,
    proficiency: Number,
    workload: Number
});
var Post = mongoose.model("Posts", postSchema);

var commentSchema = new Schema({
    aComment: {
        type: Object,
        text: String
    },
    op: String,
    to: { type: Schema.Types.ObjectId, ref: 'Professors' },
    post: String,
    opname: String,
    toname: String,
    date: Date
});
var Comment = mongoose.model("Comments", commentSchema);

async function getUserData(id) {
    try {
        const user = await User.findById(id).lean();
        return user;
    } 
    catch (error) {
        console.error('Error finding user: ', error);
        return null;
    }
}

async function getUserByEmail(email) {
    try {
        const user = await User.findOne({ email: email }).lean();
        return user;
    } 
    catch (error) {
        console.error('Error finding user by email: ', error);
        return null;
    }
}

async function getAllCourses() {
    try {
        const courses = await Course.find().lean();
        return courses;
    } 
    catch (error) {
        console.error('Error finding courses: ', error);
        return null;
    }
}

async function getCourseById(id) {
    try {
        const course = await Course.findById(id).lean();
        return course;
    } 
    catch (error) {
        console.error('Error finding course: ', error);
        return null;
    }
}

async function createCourse(name, code, description = '') {
    try {
        const course = new Course({
            name: name,
            code: code,
            description: description
        });
        await course.save();
        return course;
    } 
    catch (error) {
        console.error('Error creating course: ', error);
        return null;
    }
}

async function getAllSubjects() {
    try {
        const subjects = await Subject.find().lean();
        return subjects;
    } 
    catch (error) {
        console.error('Error finding subjects: ', error);
        return null;
    }
}

async function getSubjectById(id) {
    try {
        const subject = await Subject.findById(id).lean();
        return subject;
    } 
    catch (error) {
        console.error('Error finding subject: ', error);
        return null;
    }
}

async function createSubject(name, code, description = '') {
    try {
        const subject = new Subject({
            name: name,
            code: code,
            description: description
        });
        await subject.save();
        return subject;
    } 
    catch (error) {
        console.error('Error creating subject: ', error);
        return null;
    }
}

async function getStudentData(userId) {
    try {
        const student = await Student.findOne({ userId: userId }).populate('userId').populate('course').lean();
        return student;
    } 
    catch (error) {
        console.error('Error finding student: ', error);
        return null;
    }
}

async function createStudent(userId, studentID, courseId, bio = '') {
    try {
        const student = new Student({
            userId: userId,
            studentID: studentID,
            course: courseId,
            bio: bio
        });
        await student.save();
        return student;
    } 
    catch (error) {
        console.error('Error creating student: ', error);
        return null;
    }
}

async function getProfessorData(id) {
    try {
        const professor = await Professor.findById(id).populate('userId').populate('subjects').lean();
        return professor;
    } 
    catch (error) {
        console.error('Error finding professor: ', error);
        return null;
    }
}

async function getAllProfessorData() {
    try {
        const professors = await Professor.find().populate('userId').populate('subjects').lean();
        return professors;
    } 
    catch (error) {
        console.error('Error finding all professors: ', error);
        return null;
    }
}

async function getProfessorByUserId(userId) {
    try {
        const professor = await Professor.findOne({ userId: userId }).populate('userId').populate('subjects').lean();
        return professor;
    } 
    catch (error) {
        console.error('Error finding professor by user ID: ', error);
        return null;
    }
}

async function createProfessor(userId, teacherID, subjectIds = [], bio = '') {
    try {
        const professor = new Professor({
            userId: userId,
            teacherID: teacherID,
            subjects: subjectIds,
            bio: bio
        });
        await professor.save();
        return professor;
    } 
    catch (error) {
        console.error('Error creating professor: ', error);
        return null;
    }
}

async function getManagerData(userId) {
    try {
        const manager = await Manager.findOne({ userId: userId }).populate('userId').lean();
        return manager;
    } 
    catch (error) {
        console.error('Error finding manager: ', error);
        return null;
    }
}

async function createManager(userId) {
    try {
        const manager = new Manager({
            userId: userId
        });
        await manager.save();
        return manager;
    } 
    catch (error) {
        console.error('Error creating manager: ', error);
        return null;
    }
}

async function getAdministratorData(userId) {
    try {
        const administrator = await Administrator.findOne({ userId: userId }).populate('userId').lean();
        return administrator;
    } 
    catch (error) {
        console.error('Error finding administrator: ', error);
        return null;
    }
}

async function createAdministrator(userId) {
    try {
        const administrator = new Administrator({
            userId: userId
        });
        await administrator.save();
        return administrator;
    } 
    catch (error) {
        console.error('Error creating administrator: ', error);
        return null;
    }
}

async function getAllUsers() {
    try {
        console.log('getAllUsers function called');
        const users = await User.find().lean();
        console.log('getAllUsers found users:', users ? users.length : 'null');
        if (users && users.length > 0) {
            console.log('First user sample:', users[0]);
        }
        return users;
    } 
    catch (error) {
        console.error('Error finding all users: ', error);
        return null;
    }
}

async function deleteUser(userId) {
    try {
        console.log('Starting deletion of user:', userId);
        
        // First, check if the user exists
        const userExists = await User.findById(userId);
        if (!userExists) {
            console.log('User not found:', userId);
            return null;
        }
        
        console.log('User found:', userExists.email, 'Type:', userExists.userType);
        
        // Check database collections exist
        try {
            const managerCount = await Manager.countDocuments();
            console.log('Total managers in database:', managerCount);
        } catch (error) {
            console.log('Manager collection error:', error.message);
        }
        
        // Delete related data first - use try-catch for each operation
        try {
            const studentResult = await Student.deleteMany({ userId: userId });
            console.log('Deleted students:', studentResult.deletedCount);
        } catch (error) {
            console.log('No students to delete or error:', error.message);
        }
        
        try {
            const professorResult = await Professor.deleteMany({ userId: userId });
            console.log('Deleted professors:', professorResult.deletedCount);
        } catch (error) {
            console.log('No professors to delete or error:', error.message);
        }
        
        try {
            const managerResult = await Manager.deleteMany({ userId: userId });
            console.log('Deleted managers:', managerResult.deletedCount);
        } catch (error) {
            console.log('No managers to delete or error:', error.message);
        }
        
        try {
            const adminResult = await Administrator.deleteMany({ userId: userId });
            console.log('Deleted administrators:', adminResult.deletedCount);
        } catch (error) {
            console.log('No administrators to delete or error:', error.message);
        }
        
        // Delete posts and comments - convert userId to string
        try {
            const userIdString = userId.toString();
            const postResult = await Post.deleteMany({ op: userIdString });
            console.log('Deleted posts:', postResult.deletedCount);
        } catch (error) {
            console.log('No posts to delete or error:', error.message);
        }
        
        try {
            const userIdString = userId.toString();
            const commentResult = await Comment.deleteMany({ op: userIdString });
            console.log('Deleted comments:', commentResult.deletedCount);
        } catch (error) {
            console.log('No comments to delete or error:', error.message);
        }
        
        // Finally delete the user
        const result = await User.findByIdAndDelete(userId);
        if (result) {
            console.log('Successfully deleted user:', result.email);
            return result;
        } else {
            console.log('Failed to delete user - user not found');
            return null;
        }
    } 
    catch (error) {
        console.error('Error deleting user: ', error);
        throw error; // Re-throw to get better error handling
    }
}

async function updateUserRole(userId, newRole) {
    try {
        console.log(`Updating user ${userId} to role: ${newRole}`);
        
        // Remove from all role collections first
        await Student.deleteMany({ userId: userId });
        await Professor.deleteMany({ userId: userId });
        await Manager.deleteMany({ userId: userId });
        await Administrator.deleteMany({ userId: userId });
        
        // Update user type
        await User.updateOne({ _id: userId }, { $set: { userType: newRole } });
        
        // Create new role-specific record
        if (newRole === 'student') {
            // Get the first available course for default assignment
            const courses = await getAllCourses();
            let defaultCourseId = null;
            
            if (courses && courses.length > 0) {
                defaultCourseId = courses[0]._id;
                console.log(`Using default course: ${courses[0].name} (${defaultCourseId})`);
            } else {
                console.log('No courses available, creating a default course');
                // Create a default course if none exist
                const defaultCourse = await createCourse('General Studies', 'GEN101', 'Default course for role changes');
                defaultCourseId = defaultCourse._id;
            }
            
            return await createStudent(userId, 'TEMP_ID', defaultCourseId, '');
        } else if (newRole === 'professor') {
            return await createProfessor(userId, 'TEMP_ID', [], '');
        } else if (newRole === 'manager') {
            return await createManager(userId);
        } else if (newRole === 'administrator') {
            return await createAdministrator(userId);
        }
        
        return null;
    } 
    catch (error) {
        console.error('Error updating user role: ', error);
        return null;
    }
}

async function getProfPostData(id) {
    try {
        const review = await Post.find({to: new mongoose.Types.ObjectId(id)}).lean();
        return review;
    } 
    catch (error) {
        console.error('Error finding professor posts: ', error);
        return null;
    }
}

async function getUserPostData(id) {
    try {
        const review = await Post.find({op: id}).lean();
        return review;
    } 
    catch (error) {
        console.error('Error finding user posts: ', error);
        return null;
    }
}

async function getPostData(id) {
    try {
        const review = await Post.findById(id).lean();
        return review;
    } 
    catch (error) {
        console.error('Error finding post: ', error);
        return null;
    }
}

async function deletePost(id) {
    try {
        const result = await Post.findByIdAndDelete(id);
        return result;
    } 
    catch (error) {
        console.error('Error deleting post: ', error);
        return null;
    }
}

async function getPostCommentData(id) {
    try {
        const comm = await Comment.find({post: id}).lean();
        return comm;
    } 
    catch (error) {
        console.error('Error finding post comments: ', error);
        return null;
    }
}

async function getCommentData(id) {
    try {
        const comm = await Comment.findById(id).lean();
        return comm;
    } 
    catch (error) {
        console.error('Error finding comment: ', error);
        return null;
    }
}

async function loginUser(email, password, req) {
    try {
        // Input validation - fail securely if inputs are invalid
        if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
            console.log('Login attempt with invalid input types');
            return null;
        }
        
        // Sanitize email input
        const sanitizedEmail = email.trim().toLowerCase();
        if (!sanitizedEmail || sanitizedEmail.length > 254) { // RFC 5321 email length limit
            console.log('Login attempt with invalid email format');
            return null;
        }
        
        // Check password length (reasonable limits)
        if (password.length < 1 || password.length > 128) {
            console.log('Login attempt with invalid input format');
            return null;
        }

        const existingUser = await User.findOne({ email: sanitizedEmail }).lean();

        if (!existingUser) {
            // Use constant time comparison to prevent timing attacks
            await verifyPassword(password, '$2b$15$dummy.hash.for.timing.attack.prevention');
            return null; 
        }

        // Validate user data integrity
        if (!existingUser._id || !existingUser.email || !existingUser.userType || !existingUser.password) {
            console.log('User data integrity check failed');
            return null;
        }

        // Check account lockout status before attempting authentication
        const lockoutStatus = await checkAccountLockout(existingUser._id);
        if (lockoutStatus.isLocked) {
            console.log(`Login attempt blocked for locked account: ${sanitizedEmail}`);
            return { error: 'account_locked', reason: lockoutStatus.reason };
        }

        // Use enhanced password verification with pepper
        const passwordMatch = await verifyPassword(password, existingUser.password);
        if (!passwordMatch) {
            console.log('Authentication failed for user account');
            // Record failed login attempt for account lockout
            await recordFailedLoginAttempt(existingUser._id, sanitizedEmail);
            return null;
        }

        // Validate user type is in allowed enum
        const allowedUserTypes = ['student', 'professor', 'manager', 'administrator'];
        if (!allowedUserTypes.includes(existingUser.userType)) {
            console.log('Authentication failed - invalid account configuration');
            return null;
        }

        let userData = { ...existingUser };
        
        // Fetch additional user data based on type
        try {
            if (existingUser.userType === 'student') {
                const studentData = await getStudentData(existingUser._id);
                if (studentData) {
                    userData.studentData = studentData;
                }
            } else if (existingUser.userType === 'professor') {
                const professorData = await getProfessorByUserId(existingUser._id);
                if (professorData) {
                    userData.professorData = professorData;
                }
            } else if (existingUser.userType === 'manager') {
                const managerData = await getManagerData(existingUser._id);
                if (managerData) {
                    userData.managerData = managerData;
                }
            } else if (existingUser.userType === 'administrator') {
                const administratorData = await getAdministratorData(existingUser._id);
                if (administratorData) {
                    userData.administratorData = administratorData;
                }
            }
        } catch (dataError) {
            console.error('Error fetching additional user data:', dataError);
            // Continue with login even if additional data fails to load
        }

        // Create session data with validation
        const sessionData = {
            _id: existingUser._id.toString(),
            email: existingUser.email,
            firstName: existingUser.firstName,
            lastName: existingUser.lastName,
            userType: existingUser.userType
        };
        
        // Validate session data before setting
        if (!sessionData._id || !sessionData.email || !sessionData.userType) {
            console.log('Session data validation failed');
            return null;
        }

        req.session.user = sessionData;

        // Reset account lockout on successful login
        await resetAccountLockout(existingUser._id);

        return userData;
    } 
    catch (error) {
        console.error('Error during login: ', error);
        // Fail securely - don't expose internal errors
        return null;
    }
}

async function registerUser(firstName, lastName, email, password, userType, additionalData) {
    try {
        // Validate password strength before processing
        const passwordValidation = validatePasswordStrength(password);
        if (!passwordValidation.isValid) {
            return { 
                success: false, 
                error: 'Password validation failed', 
                details: passwordValidation.errors 
            };
        }
        
        // Check for length-based patterns (for existing users during password changes)
        // Note: For new registrations, this check is not applicable since there's no history yet

        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return { success: false, error: 'User already exists' };
        }

        // Use enhanced password hashing with pepper
        const hashedPassword = await hashPassword(password);

        const user = new User({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: hashedPassword,
            userType: userType,
            passwordChangedAt: new Date() // Track when password was set
        });
        await user.save();
        
        // Add password to history for future validation
        await addPasswordToHistory(user._id, hashedPassword);

        let specificUserData = null;
        
        if (userType === 'student') {
            specificUserData = await createStudent(
                user._id, 
                additionalData.studentID, 
                additionalData.courseId, 
                additionalData.bio || ''
            );
        } else if (userType === 'professor') {
            specificUserData = await createProfessor(
                user._id, 
                additionalData.teacherID, 
                additionalData.subjectIds || [], 
                additionalData.bio || ''
            );
        } else if (userType === 'manager') {
            specificUserData = await createManager(user._id);
        } else if (userType === 'administrator') {
            specificUserData = await createAdministrator(user._id);
        }

        return { 
            success: true, 
            user: user, 
            specificUserData: specificUserData 
        };
    } 
    catch (error) {
        console.error('Error during registration: ', error);
        return { success: false, error: 'Registration failed' };
    }
}

// Enhanced password change function with all complexity requirements
async function changePassword(userId, currentPassword, newPassword) {
    try {
        // Get user
        const user = await User.findById(userId);
        if (!user) {
            return { success: false, error: 'User not found' };
        }
        
        // Verify current password
        const isCurrentPasswordValid = await verifyPassword(currentPassword, user.password);
        if (!isCurrentPasswordValid) {
            return { success: false, error: 'Current password is incorrect' };
        }
        
        // Validate new password strength
        const passwordValidation = validatePasswordStrength(newPassword);
        if (!passwordValidation.isValid) {
            return { 
                success: false, 
                error: 'Password validation failed', 
                details: passwordValidation.errors 
            };
        }
        
        // Check password history
        const historyCheck = await checkPasswordHistory(userId, newPassword);
        if (!historyCheck.isValid) {
            return { success: false, error: historyCheck.error };
        }
        
        // Check for length-based patterns
        const lengthPatternCheck = await checkLengthPatterns(userId, newPassword.length);
        if (!lengthPatternCheck.isValid) {
            return { success: false, error: lengthPatternCheck.error };
        }
        
        // Hash new password
        const hashedNewPassword = await hashPassword(newPassword);
        
        // Store old password in history before updating
        await addPasswordToHistory(userId, user.password);
        
        // Update user password and timestamp
        user.password = hashedNewPassword;
        user.passwordChangedAt = new Date();
        await user.save();
        
        return { success: true };
    } catch (error) {
        console.error('Error changing password:', error);
        return { success: false, error: 'Password change failed' };
    }
}

async function resetPasswordDirectly(userId, newPassword) {
    try {
        // Validate new password
        const passwordValidation = validatePasswordStrength(newPassword);
        if (!passwordValidation.isValid) {
            return { 
                success: false, 
                error: 'password_validation', 
                details: passwordValidation.errors 
            };
        }
        
        // Hash new password
        const hashedPassword = await hashPassword(newPassword);
        
        // Update user password
        await User.findByIdAndUpdate(userId, {
            password: hashedPassword,
            passwordChangedAt: new Date()
        });
        
        // Add to password history
        await addPasswordToHistory(userId, hashedPassword);
        
        return { success: true };
    } catch (error) {
        console.error('Error resetting password:', error);
        return { success: false, error: 'Failed to reset password' };
    }
}

module.exports = {  
    getUserData,
    getUserByEmail,
    
    getAllCourses,
    getCourseById,
    createCourse,
    
    getAllSubjects,
    getSubjectById,
    createSubject,
    
    getStudentData,
    createStudent,
    
    getProfessorData,
    getAllProfessorData,
    getProfessorByUserId,
    createProfessor,
    
    getManagerData,
    createManager,
    
    getAdministratorData,
    createAdministrator,
    getAllUsers,
    deleteUser,
    updateUserRole,
    
    getUserPostData,
    getPostData,
    getProfPostData,
    deletePost,
    
    getPostCommentData,
    getCommentData,
    
    loginUser,
    registerUser,
    
    // Password security functions
    validatePasswordStrength,
    hashPassword,
    verifyPassword,
    checkPasswordHistory,
    checkPasswordAge,
    addPasswordToHistory,
    changePassword,
    checkLengthPatterns,
    getLengthClassification,
    
    // Account lockout functions
    checkAccountLockout,
    recordFailedLoginAttempt,
    resetAccountLockout,
    unlockAccount,
    
    // Password reset functions
    generatePasswordResetToken,
    validatePasswordResetToken,
    verifySecurityQuestions,
    resetPasswordWithToken,
    resetPasswordDirectly,
    setupSecurityQuestions,
    getSecurityQuestions,
    cleanupExpiredTokens,
    validateSecurityAnswer,
    
    // Security questions and reset token models
    PasswordResetToken,
    SecurityQuestions,
    PasswordResetAttempt,
    
    // Security questions configuration
    SECURITY_QUESTIONS,
    PASSWORD_RESET_CONFIG,
    
    User,
    Student,
    Professor,
    Manager,
    Administrator,
    Course,
    Subject,
    Post,
    Comment,
    PasswordHistory
}