const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

var Schema = mongoose.Schema;

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
    }
});
var User = mongoose.model("Users", userSchema);

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
        const existingUser = await User.findOne({ email: email }).lean();

        if (!existingUser) {
            return null; 
        }

        const passwordMatch = await bcrypt.compare(password, existingUser.password);
        if (!passwordMatch) {
            return null;
        }

        let userData = { ...existingUser };
        
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

        req.session.user = {
            _id: existingUser._id.toString(),
            email: existingUser.email,
            firstName: existingUser.firstName,
            lastName: existingUser.lastName,
            userType: existingUser.userType
        };

        return userData;
    } 
    catch (error) {
        console.error('Error during login: ', error);
        return null;
    }
}

async function registerUser(firstName, lastName, email, password, userType, additionalData) {
    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return { success: false, error: 'User already exists' };
        }

        const hashedPassword = await bcrypt.hash(password, 15);

        const user = new User({
            firstName: firstName,
            lastName: lastName,
            email: email,
            password: hashedPassword,
            userType: userType
        });
        await user.save();

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
    
    User,
    Student,
    Professor,
    Manager,
    Administrator,
    Course,
    Subject,
    Post,
    Comment
}