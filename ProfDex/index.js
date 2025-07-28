
const express = require('express');
const app = express();
const PORT = 3000;
const handlebars = require('express-handlebars');
const { 
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
    Course,
    Subject,
    Post,
    Comment
} = require(__dirname + '/db' + '/controller.js');

const mongoose = require('mongoose');
const session = require('express-session');
const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 15;

mongoose.connect(process.env.MONGODB_CONNECT_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

mongoose.connection.on('error', (err) => {
    console.log('err', err);
});

mongoose.connection.on('connected', (err, res) => {
    console.log('MongoDB connected successfully!');
});

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.listen(PORT, () => console.log(`Server listening on port: ${PORT}`));

app.engine('hbs', handlebars.engine({ 
    extname: 'hbs',
    helpers: {
        divide: function(a, b) {
            return Math.round(a / b);
        },
        eq: function(a, b) {
            if (a == null || b == null) return false;
            return a.toString() === b.toString();
        },
        ne: function(a, b) {
            if (a == null || b == null) return false;
            return a.toString() !== b.toString();
        },
        and: function() {
            var args = Array.prototype.slice.call(arguments, 0, -1);
            return args.every(Boolean);
        },
        or: function() {
            var args = Array.prototype.slice.call(arguments, 0, -1);
            return args.some(Boolean);
        },
        ifCond: function(v1, v2, options) {
            if (v1 === v2) {
                return options.fn(this);
            }
            return options.inverse(this);
        }
    }
}));
app.set('view engine', 'hbs');
app.set('views', __dirname + '/views');

app.set('view cache', false);

var current;

const sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_CONNECT_URI,
    mongoOptions: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    },
    collectionName: 'sessions',
});

app.use(
    session({
        store: sessionStore,
        secret: 'Placeholder',
        resave: false,
        saveUninitialized: true,
        cookie: {
            maxAge: 24 * 60 * 60 * 1000,
            expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
            sameSite: 'strict',
        },
    })
);

app.use((req, res, next) => {
    res.locals.loggedInUser = req.session.user;
    next();
});

function isLoggedIn(req, res, next) {
    if (req.session.user) {
        next();
    } 
    else {
        res.redirect('/login');
    }
}

app.route('/').get(async (req, res) => {
    var data = await getAllProfessorData();
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/home_page.hbs', {
        data,
        userType,
        layout: false
    });
});

app.route('/createpost')
.get(isLoggedIn, async (req, res) => {
    if (req.session.user && req.session.user.userType === 'professor') {
        return res.redirect('/?error=not_allowed');
    }
    const errors = {};
    if (req.query.error === 'professor_error') {
        errors.professor_error = true;
    }
    if (req.query.error === 'validation_error') {
        errors.validation_error = true;
    }

    const professors = await getAllProfessorData();
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/createpost.hbs', { 
        layout: false, 
        errors, 
        professors,
        userType
    });
})
.post(isLoggedIn, async (req, res) => {
    if (req.session.user && req.session.user.userType === 'professor') {
        return res.redirect('/?error=not_allowed');
    }
    try {
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        var { professorId, course, text, generosity, difficulty, engagement, proficiency, workload} = req.body;
        
        if (!professorId || !course || !text) {
            res.redirect('/createpost?error=validation_error');
            return;
        }
        
        if (text.length < 10) {
            res.redirect('/createpost?error=validation_error');
            return;
        }
        
        var professorData = await getProfessorData(professorId);

        if (!professorData) {
            res.redirect('/createpost?error=professor_error');
            return;
        }

        const newPost = new Post({
            aPost : {
                type : Object,
                "text": text,
            },
            "op": myId,
            "to": professorData._id,
            "course": course,
            "opname": userData.firstName + " " + userData.lastName,
            "toname": professorData.userId.firstName + " " + professorData.userId.lastName,
            "generosity": generosity * 2,
            "difficulty": difficulty * 2,
            "engagement": engagement * 2,
            "proficiency": proficiency * 2,
            "workload": workload * 2
        });

        await newPost.save();

        res.redirect('/reviewlist?id=' + professorData._id);
    } 
    catch (error) {
        console.error('Error saving review: ', error);
        res.redirect('/createpost?error=validation_error');
    }
});

app.route('/editprofile')
.get(isLoggedIn, async (req, res) => {
    const errors = {};
    if (req.query.error === 'validation_error') {
        errors.validation_error = true;
    }
    if (req.query.success === 'true') {
        errors.success = true;
    }
    
    var myId = req.session.user._id;
    var userData = await getUserData(myId);
    var studentData = null;
    var courses = null;
    var subjects = null;
    
    if (req.session.user.userType === 'student') {
        studentData = await getStudentData(myId);
        courses = await getAllCourses();
    }
    
    if (req.session.user.userType === 'professor') {
        subjects = await getAllSubjects();
    }
    
    var postData = await getUserPostData(myId);
    res.render(__dirname + '/views' + '/editprofile_page.hbs', {
        userData,
        studentData,
        postData,
        myId,
        errors,
        courses,
        subjects,
        layout: false
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
      const myId = req.session.user._id;
      const { firstName, lastName, email, studentID, course, bio } = req.body;

      if (!firstName || !lastName || !email) {
        res.redirect('/editprofile?error=validation_error');
        return;
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        res.redirect('/editprofile?error=validation_error');
        return;
      }

      await User.updateOne(
        { _id: myId },
        {
          $set: {
            firstName: firstName,
            lastName: lastName,
            email: email
          }
        }
      );

      if (req.session.user.userType === 'student') {
        if (!studentID || !course) {
          res.redirect('/editprofile?error=validation_error');
          return;
        }

        await Student.updateOne(
          { userId: myId },
          {
            $set: {
              studentID: studentID,
              course: course,
              bio: bio || ''
            }
          }
        );
      }
      
      if (req.session.user.userType === 'professor') {
        const { subjects } = req.body;
        
        if (subjects && Array.isArray(subjects)) {
          await Professor.updateOne(
            { userId: myId },
            {
              $set: {
                subjects: subjects
              }
            }
          );
        }
      }

      res.redirect('/editprofile?success=true');
    } 
    catch (error) {
      console.error('Error updating profile: ', error);
      res.redirect('/editprofile?error=validation_error');
    }
});


app.route('/login')
.get(async (req, res) => {
    const errors = {};
    if (req.query.error === 'password_mismatch') {
        errors.password_mismatch = true;
    }
    if (req.query.error === 'invalid_credentials') {
        errors.invalid_credentials = true;
    }
    if (req.query.error === 'registration_error') {
        errors.registration_error = true;
    }
    
    const courses = await getAllCourses();
    const subjects = await getAllSubjects();
    
    res.render(__dirname + '/views' + '/LR_page.hbs', { 
        layout: false, 
        errors,
        courses,
        subjects
    });
})
.post(async (req, res) => {
    try {
        const { email, password, registerFirstName, registerLastName, registerEmail, registerPassword, confirmPassword, userType, studentID, course, teacherID, subjects } = req.body;
        
        console.log('Registration attempt:', { 
            email, 
            registerFirstName, 
            registerLastName, 
            registerEmail, 
            userType, 
            studentID, 
            course, 
            teacherID, 
            subjects 
        });

        if (email && password) {
            const loggedInUser = await loginUser(email, password, req);

            if (loggedInUser) {
                const userType = loggedInUser.userType;
                if (userType === 'student') {
                    res.redirect('/editprofile');
                } else if (userType === 'professor') {
                    res.redirect('/');
                } else if (userType === 'manager') {
                    res.redirect('/');
                } else {
                    res.redirect('/login?error=invalid_credentials');
                }
            } 
            else {
                res.redirect('/login?error=invalid_credentials');
                return;
            }
        } 
        else if (registerFirstName && registerLastName && registerEmail && registerPassword && confirmPassword && userType) {
            if (registerPassword !== confirmPassword) {
                res.redirect('/login?error=password_mismatch');
                return;
            }
            
            let additionalData = {};
            
            if (userType === 'student') {
                if (!studentID || !course) {
                    res.redirect('/login?error=registration_error');
                    return;
                }
                additionalData = { studentID, courseId: course };
            } else if (userType === 'professor') {
                if (!teacherID) {
                    res.redirect('/login?error=registration_error');
                    return;
                }
                additionalData = { teacherID, subjectIds: subjects || [] };
            }
            
            console.log('Additional data for registration:', additionalData);
            const result = await registerUser(registerFirstName, registerLastName, registerEmail, registerPassword, userType, additionalData);
            console.log('Registration result:', result);
            
            if (result.success) {
                const loggedInUser = await loginUser(registerEmail, registerPassword, req);
                if (loggedInUser) {
                    if (userType === 'student') {
                        res.redirect('/editprofile');
                    } else if (userType === 'professor') {
                        res.redirect('/');
                    } else if (userType === 'manager') {
                        res.redirect('/');
                    }
                } else {
                    res.redirect('/login?error=invalid_credentials');
                }
            } else {
                res.redirect('/login?error=registration_error');
            }
        } 
        else {
            res.redirect('/login?error=invalid_data');
        }
    } 
    catch (error) {
        console.error('Error during login/registration: ', error);
        console.error('Error stack:', error.stack);
        res.redirect('/login?error=registration_error');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session: ', err);
        }
        res.redirect('/');
    });
});

app.route('/reviewlist')
.get(async (req, res) => {
    var professorId = req.query.id;
    var professorData = await getProfessorData(professorId);
    var postData = await getProfPostData(professorId);
    const userType = req.session.user ? req.session.user.userType : '';
    let postUserTypes = [];
    if (postData && postData.length) {
        const userIds = postData.map(p => p.op);
        const users = await Promise.all(userIds.map(async (id) => {
            const user = await getUserData(id);
            return user ? user.userType : null;
        }));
        postUserTypes = users;
    }
    res.render(__dirname + '/views' + '/reviewlist.hbs', {
        professorData,
        postData,
        userType,
        postUserTypes,
        loggedInUser: req.session.user,
        layout: false
    });
});

app.route('/viewreview')
.get(async (req, res) => {
    var postId = req.query.id;
    var postData = await getPostData(postId);
    var professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
    var commentData = await getPostCommentData(postId);
    let commentUserTypes = [];
    if (commentData && commentData.length) {
        const userIds = commentData.map(c => c.op);
        const users = await Promise.all(userIds.map(async (id) => {
            const user = await getUserData(id);
            return user && user.userType ? user.userType : '';
        }));
        commentUserTypes = users;
    }
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/viewreview.hbs', {
        professorData,
        postData,
        commentData,
        commentUserTypes,
        userType,
        loggedInUser: req.session.user,
        layout: false
    });
})
.post(async (req, res) => {
    try {
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        const { commentText, post, to, toname } = req.body;

        const newComment = new Comment({
            aComment : {
                text: commentText,
            },
            op: myId,
            to: to,
            post: post,
            opname: userData.firstName + ' ' + userData.lastName,
            toname: toname,
            date: new Date()
        });

        await newComment.save();

        res.redirect('/viewreview?id=' + post);
    } 
    catch (error) {
        console.error('Error saving comment: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
});

app.post('/deletecomment', isLoggedIn, async (req, res) => {
    try {
        const { commentId, postId } = req.body;
        const myId = req.session.user._id;
        const comment = await Comment.findById(commentId);
        if (!comment) {
            const msg = 'Comment not found';
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(404).json({ error: msg });
            }
            return res.redirect('/viewreview?id=' + postId);
        }
        const isManager = req.session.user && req.session.user.userType === 'manager';
        if (comment.op !== myId && !isManager) {
            const msg = 'You can only delete your own comments unless you are a manager';
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(403).json({ error: msg });
            }
            return res.redirect('/viewreview?id=' + postId);
        }
        await Comment.findByIdAndDelete(commentId);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.json({ success: true });
        }
        res.redirect('/viewreview?id=' + postId);
    } catch (error) {
        console.error('Error deleting comment:', error);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(500).json({ error: 'Server error', details: error.message });
        }
        res.redirect('/viewreview?id=' + (req.body.postId || ''));
    }
});

app.post('/delete-review-and-comments', isLoggedIn, async (req, res) => {
    try {
        if (!req.session.user || req.session.user.userType !== 'manager') {
            return res.status(403).send('Forbidden');
        }
        const { reviewId } = req.body;
        await Comment.deleteMany({ post: reviewId });
        await deletePost(reviewId);
        res.redirect('/');
    } catch (error) {
        console.error('Error deleting review and comments:', error);
        res.status(500).send('Server error');
    }
});

app.route('/reply')
.get(isLoggedIn, async (req, res) => {
    var commentID = req.query.id;
    var commentData = await getCommentData(commentID);
    var userData = await getUserData(new mongoose.Types.ObjectId(commentData.op));
    res.render(__dirname + '/views' + '/reply.hbs', {
        commentData,
        userData,
        layout: false
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
        if (!req.session.user) {
            console.error('No user in session');
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(401).json({ error: 'Not logged in' });
            }
            return res.render(__dirname + '/views/error.hbs', { layout: false });
        }
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        if (!userData || !userData.firstName || !userData.lastName) {
            console.error('User data missing or malformed:', userData);
            if (req.xhr || req.headers.accept.indexOf('json') > -1) {
                return res.status(400).json({ error: 'User data error' });
            }
            return res.render(__dirname + '/views/error.hbs', { layout: false });
        }
        const { commentText, post, to, toname } = req.body;
        const newComment = new Comment({
            aComment : {
                text: commentText,
            },
            op: myId,
            to: to,
            post: post,
            opname: userData.firstName + ' ' + userData.lastName,
            toname: toname,
            date: new Date()
        });
        await newComment.save();
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.json({ success: true });
        }
        res.redirect('/viewreview?id=' + post);
    } 
    catch (error) {
        console.error('Error saving comment: ', error);
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(500).json({ error: 'Server error', details: error.message });
        }
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
});

app.route('/viewcomments')
.get(async (req, res) => {
    var postId = req.query.id;
    var postData = await getPostData(postId);
    var professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
    var commentData = await getPostCommentData(postId);
    let commentUserTypes = [];
    if (commentData && commentData.length) {
        const userIds = commentData.map(c => c.op);
        const users = await Promise.all(userIds.map(async (id) => {
            const user = await getUserData(id);
            return user && user.userType ? user.userType : '';
        }));
        commentUserTypes = users;
    }
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/viewcomments.hbs', {
        professorData,
        postData,
        commentData,
        commentUserTypes,
        userType,
        loggedInUser: req.session.user,
        layout: false
    });
});

app.route('/viewprof')
.get(async (req, res) => {
    try {
        var professorId = req.query.id;
        var professorData = await getProfessorData(professorId);
        var postData = await getProfPostData(professorId);
        res.render(__dirname + '/views' + '/viewprof.hbs', {
            professorData,
            postData,
            layout: false
        });
    }
    catch {
        res.redirect('/login');
    }
})
.get(async (req, res) => {
    var commentId = req.query.id;
    var commentData = await getCommentData(commentId);
    var userData = await getUserData(commentData.op);
    let commentUserTypes = [];
    if (commentData) {
        const user = await getUserData(commentData.op);
        commentUserTypes = [user ? user.userType : null];
    }
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/reply.hbs', {
        commentData,
        userData,
        commentUserTypes,
        userType,
        loggedInUser: req.session.user,
        layout: false
    });
})

app.route('/viewuser')
.get(async (req, res) => {
    var postId = req.query.id;
    var postData = await getPostData(postId);
    var professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
    var commentData = await getPostCommentData(postId);
    let commentUserTypes = [];
    if (commentData && commentData.length) {
        const userIds = commentData.map(c => c.op);
        const users = await Promise.all(userIds.map(async (id) => {
            const user = await getUserData(id);
            return user ? user.userType : null;
        }));
        commentUserTypes = users;
    }
    const userType = req.session.user ? req.session.user.userType : null;
    res.render(__dirname + '/views' + '/viewcomments.hbs', {
        professorData,
        postData,
        commentData,
        commentUserTypes,
        userType,
        loggedInUser: req.session.user,
        layout: false
    });
})
.post(isLoggedIn, async (req, res) => {
    try {
        const { reviewId } = req.body;
        const myId = req.session.user._id;
        
        const reviewData = await getPostData(reviewId);
        
        if (!reviewData) {
            res.status(404).json({ error: 'Review not found' });
            return;
        }
        
        const isManager = req.session.user && req.session.user.userType === 'manager';
        if (reviewData.op !== myId && !isManager) {
            res.status(403).json({ error: 'You can only delete your own reviews unless you are a manager' });
            return;
        }
        
        const result = await deletePost(reviewId);
        
        if (result) {
            res.redirect('/editprofile');
        } else {
            res.status(500).json({ error: 'Failed to delete review' });
        }
    } 
    catch (error) {
        console.error('Error deleting review: ', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.route('/editreview')
.get(isLoggedIn, async (req, res) => {
    try {
        const { reviewId } = req.query;
        const myId = req.session.user._id;
        
        const reviewData = await getPostData(reviewId);
        
        if (!reviewData) {
            res.redirect('/editprofile');
            return;
        }
        
        if (reviewData.op !== myId) {
            res.redirect('/editprofile');
            return;
        }
        
        res.render(__dirname + '/views' + '/editreview.hbs', {
            reviewData,
            layout: false
        });
    } 
    catch (error) {
        console.error('Error loading review for editing: ', error);
        res.redirect('/editprofile');
    }
})
.post(isLoggedIn, async (req, res) => {
    try {
        const { reviewId, text, generosity, difficulty, engagement, proficiency, workload } = req.body;
        const myId = req.session.user._id;
        
        const reviewData = await getPostData(reviewId);
        
        if (!reviewData) {
            res.status(404).json({ error: 'Review not found' });
            return;
        }
        
        if (reviewData.op !== myId) {
            res.status(403).json({ error: 'You can only edit your own reviews' });
            return;
        }
        
        if (!text || text.length < 10) {
            res.redirect('/editreview?reviewId=' + reviewId + '&error=validation_error');
            return;
        }
        
        await post.updateOne(
            { _id: reviewId },
            {
                $set: {
                    'aPost.text': text,
                    'generosity': generosity * 2,
                    'difficulty': difficulty * 2,
                    'engagement': engagement * 2,
                    'proficiency': proficiency * 2,
                    'workload': workload * 2
                }
            }
        );
        
        res.redirect('/editprofile?success=true');
    } 
    catch (error) {
        console.error('Error updating review: ', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.route('/help').all(async(req, res) => {
    try{

        res.render(__dirname + '/views' + '/help.hbs', { layout: false });

    }catch(error) {
        console.error('Error during help: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
})