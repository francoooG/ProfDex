const express = require('express');
const app = express();
const PORT = 3000;
const handlebars = require('express-handlebars');
const { getProfessorData, 
		getProfessorDataFromName,
		getAllProfessorData,
        getUserData, 
		getUserPostData, 
		getPostData, 
		getProfPostData, 
		getPostCommentData, 
		getCommentData, 
		comment, 
		loginUser,
		user,
		post
} = require(__dirname + '/db' + '/controller.js');

const mongoose = require('mongoose');
const session = require('express-session');
const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 15;

mongoose.connect('mongodb://127.0.0.1:27017/Profdex', {
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

app.engine('hbs', handlebars.engine({ extname: 'hbs' }));
app.set('view engine', 'hbs');
app.set('views', __dirname + '/views');

app.set('view cache', false);

var current;

const sessionStore = MongoStore.create({
    mongoUrl: 'mongodb://127.0.0.1:27017/Profdex',
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
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
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
	//List of professor data
    var data = await getAllProfessorData();

	res.render(__dirname + '/views' + '/home_page.hbs', {
		data,
		layout: false
	});
});

app.route('/createpost')
.get(isLoggedIn, async (req, res) => {
	const errors = {};
    if (req.query.error === 'professor_error') {
        errors.professor_error = true;
    }

    res.render(__dirname + '/views' + '/createpost.hbs', { layout: false, errors });
})
.post(isLoggedIn, async (req, res) => {
    try {
        var myId = req.session.user._id;
        var userData = await getUserData(myId);
        var { firstname, lastname, course, text, generosity, difficulty, engagement, proficiency, workload} = req.body;
        var professorData = await getProfessorDataFromName(firstname, lastname);

        if (!professorData) {
            res.redirect('/createpost?error=professor_error');
            return;
        }

        const newPost = new post({
            aPost : {
                type : Object,
                "text": text,
            },
            "op": myId,
            "to": professorData._id,
            "course": course,
            "opname": userData.aUser.username,
            "toname": professorData.aProfessor.title + " " + professorData.aProfessor.lastname,
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
        console.error('Error saving comment: ', error);
        res.render(__dirname + '/views/createpost.hbs', { layout: false });
    }
});

app.route('/editprofile')
.get(isLoggedIn, async (req, res) => {
	var myId = req.session.user._id;
	var userData = await getUserData(myId);
	var postData = await getUserPostData(myId);
	res.render(__dirname + '/views' + '/editprofile_page.hbs', {
		userData,
		postData,
		myId,
		layout: false
	});
})
.post(isLoggedIn, async (req, res) => {
    try {
      const myId = req.session.user._id;
      const userData = await getUserData(myId);

      const { username, email, idno, major, user_bio } = req.body;

      await user.updateOne(
        { _id: myId },
        {
          $set: {
            'aUser.username': username,
            'aUser.email': email,
            'aUser.idbatch': idno,
            'aUser.course': major,
            'aUser.bio': user_bio,
          },
        }
      );

      res.redirect('/editprofile');
    } 
	catch (error) {
      console.error('Error updating profile: ', error);
      res.render(__dirname + '/views/error.hbs', { layout: false });
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
    res.render(__dirname + '/views' + '/LR_page.hbs', { layout: false, errors });
})
.post(async (req, res) => {
	try {
		const { username, password, registerusername, registerpassword, confirmpassword, major, batchno, email } = req.body;

		if (username && password) {
		// Login
			const loggedInUser = await loginUser(username, password, req);

			if (loggedInUser) {
				res.redirect(`/editprofile?id=${loggedInUser._id}`);
			} 
			else {
				res.redirect('/login?error=invalid_credentials');
				return;
			}
		} 
		else if (registerusername && registerpassword && confirmpassword && major && batchno && email &&
		         !(await loginUser(registerusername, registerpassword, req))) {
			// Register
			if (registerpassword !== confirmpassword) {
                res.redirect('/login?error=password_mismatch');
                return;
            }
			
			const hashedPassword = await bcrypt.hash(registerpassword, saltRounds);
			
			const newUser = new user({
				aUser: {
					"type": Object,
					"username": registerusername,
					"course": major,
					"idbatch": batchno,
					"bio": String,
					"password": hashedPassword,
					"email": email
				}
			});

			await newUser.save();

			const loggedInUser = await loginUser(registerusername, registerpassword, req);

			res.redirect(`/editprofile?id=${loggedInUser._id}`);
		} 
		else {
			res.redirect('/login?error=invalid_data');
		}
	} 
	catch (error) {
		console.error('Error during login/registration: ', error);
		res.render(__dirname + '/views/error.hbs', { layout: false });
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
    res.render(__dirname + '/views' + '/reviewlist.hbs', {
		professorData,
		postData,
		layout: false
    });
});

app.route('/viewreview')
.get(async (req, res) => {
    var postId = req.query.id;
    var postData = await getPostData(postId);
	var professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
    res.render(__dirname + '/views' + '/viewreview.hbs', {
		professorData,
		postData,
		layout: false
    });
})
.post(async (req, res) => {
    try {
		var myId = req.session.user._id;
		var userData = await getUserData(myId);
        const { commentText, post, to, toname } = req.body;

        const newComment = new comment({
            aComment : {
				type : Object,
				text: commentText,
			},
            op: myId,
            to: to,
            post: post,
            opname: userData.aUser.username,
            toname: toname,
            date: new Date()
        });

        await newComment.save();

        res.redirect('/viewcomments?id=' + post);
    } 
	catch (error) {
        console.error('Error saving comment: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
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
		var myId = req.session.user._id;
		var userData = await getUserData(myId);
        const { commentText, post, to, toname } = req.body;

        const newComment = new comment({
            aComment : {
				type : Object,
				text: commentText,
			},
            op: myId,
            to: to,
            post: post,
            opname: userData.aUser.username,
            toname: toname,
            date: new Date()
        });

        await newComment.save();

        res.redirect('/viewcomments?id=' + post);
    } 
	catch (error) {
        console.error('Error saving comment: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
});

app.route('/viewcomments')
.get(async (req, res) => {
	var postID = req.query.id;
	var commentData = await getPostCommentData(postID);
	var postData = await getPostData(postID);
	var professorData = await getProfessorData(new mongoose.Types.ObjectId(postData.to));
    res.render(__dirname + '/views' + '/viewcomments.hbs', {
		commentData,
		postData,
		professorData,
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
.post(async (req, res) => {
    try {
        var { search } = req.body;
        var professorData = await getProfessorDataFromName(search.split(" ")[0], search.split(" ")[1]);

        if (professorData) {
            var postData = await getProfPostData(professorData._id);
			
            res.render(__dirname + '/views' + '/viewprof.hbs', {
                professorData,
                postData,
                layout: false
            });
        } 
		else {
            res.redirect('/');
        }
    } 
	catch (error) {
        console.error('Error during professor search: ', error);
        res.render(__dirname + '/views/error.hbs', { layout: false });
    }
});

app.route('/viewuser')
.get(async (req, res) => {
	var userId = req.query.id;
    var userData = await getUserData(userId);
	var postData = await getUserPostData(userId);
    res.render(__dirname + '/views' + '/viewuser.hbs', {
		userData,
		postData,
		layout: false
    });
});

app.route('/help').all(async(req, res) => {
	try{

		res.render(__dirname + '/views' + '/help.hbs', { layout: false });

	}catch(error) {
		console.error('Error during help: ', error);
		res.render(__dirname + '/views/error.hbs', { layout: false });
	}
})