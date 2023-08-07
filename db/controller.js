const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

var Schema = mongoose.Schema;

//Professors
var profSchema = new Schema({
	aProfessor : {
		type: Object,
		"firstName":  String,
		"lastName": String,
		"title":  String,
		"course":  String,
		"sterm": String,
		"bio": String
	}
});
var prof = mongoose.model("Profs", profSchema);

async function getProfessorData(id) {
    try {
        const professor = await prof.findById(id).lean();
        return professor;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

async function getAllProfessorData() {
    try {
        const professor = await prof.find().lean();
        return professor;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

async function getProfessorDataFromName(firstname, lastname) {
    try {
        const professor = await prof.findOne({ "aProfessor.firstname": firstname, "aProfessor.lastname": lastname }).lean();
        return professor;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

//Users
var userSchema = new Schema({
    aUser : {
		"type": Object,
		"username": String,
		"course": String,
		"idbatch": String,
		"bio": String,
		"password": String,
		"email": String
	}
});
var user = mongoose.model("Users", userSchema);

async function getUserData(id) {
    try {
        const student = await user.findById(id).lean();
        return student;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

//Posts
var postSchema = new Schema({
    aPost : {
		type : Object,
		"text": String,
	},
	"op": String,
	"to": String,
	"course": String,
	"opname": String,
	"toname": String,
	"difficulty": Number,
    "engagement": Number,
    "generosity": Number,
    "proficiency": Number,
    "workload": Number
});
var post = mongoose.model("Posts", postSchema);

async function getProfPostData(id) {
    try {
        const review = await post.find({to: id}).lean();
        return review;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

async function getUserPostData(id) {
    try {
        const review = await post.find({op: id}).lean();
        return review;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

async function getPostData(id) {
    try {
        const review = await post.findById(id).lean();
        return review;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

//Comments
var commentSchema = new Schema({
    aComment : {
		type : Object,
		"text": String,
	},
	"op": String,
	"to": String,
	"post": String,
	"opname": String,
	"toname": String,
	"date" : Date
});
var comment = mongoose.model("Comments", commentSchema);

async function getPostCommentData(id) {
    try {
        const comm = await comment.find({post: id}).lean();
        return comm;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

async function getCommentData(id) {
    try {
        const comm = await comment.findById(id).lean();
        return comm;
    } 
	catch (error) {
        console.error('Error finding data: ', error);
        return null;
    }
}

async function loginUser(username, password, req) {
    try {
        const existingUser = await user.findOne({ 'aUser.username': {'$regex': `^${username}$`, $options: 'i'} }).lean();

        if (!existingUser || !(await bcrypt.compare(password, existingUser.aUser.password))) {
            return null; // User not found
        }

        // Storing to session
        req.session.user = {
            _id: existingUser._id.toString(), // Convert to string to be used in op attributes
            username: existingUser.aUser.username
        };

        return existingUser; // User found
    } 
	catch (error) {
        console.error('Error finding user: ', error);
        return null;
    }
}


module.exports = {  
	getProfessorData,
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
}