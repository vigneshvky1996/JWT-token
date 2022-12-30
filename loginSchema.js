const mongoose = require('mongoose');
const login = new mongoose.Schema({
    userName :{
        type : String
    },
    password :{
        type : String
    }
})
module.exports = mongoose.model('loginDetails' , login);