require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const loginDetails = require("./schema/loginSchema.js");

mongoose.connect("mongodb://127.0.0.1:27017/login",{ useNewUrlParser : true});
const con = mongoose.connection;

const app = express();
app.use(express.json());

con.on("open", ()=>{
    console.log("connected successfully");
})

//view all user details
app.get("/users", async(req,res)=>{
    try {
        const users = await loginDetails.find({},{password : 0 });
        res.json(users);
        
    } catch (error) {
        res.send(error)
    }
})

//creating new user
app.post("/signup" , async(req,res)=>{
    try {
        const hashedPassword = await  bcrypt.hash(req.body.password, 10);
        const newUser = new loginDetails({
            userName : req.body.userName,
            password : hashedPassword
        })
        await newUser.save();
        res.status(200).json({status : 200 , message :"signedup successful"});
    } catch (error) {
        res.status(400).json({message : "error occured", error :error});
    }
})

//verifying user details for log-in purpose
app.post("/login" , async(req,res)=>{
    const userData = await loginDetails.findOne({userName : req.body.userName});
    // console.log(user); used for checking whether we receiving data or not.
    if(userData == null){
        return res.status(409).json({status:409,message:'user does not exist'});
    } 
    try {
        if (await bcrypt.compare(req.body.password , userData.password)){
            //return res.send("logged-in successfully");
           const aToken = await jwt.sign({user : userData} , process.env.ACCESS_TOKEN_SECRET,{expiresIn : "90s"});
          // return res.json({accessToken : aToken});
           res.status(200).json({status: 200, message: "logged in successful" , accessToken : aToken });
        }
        else{
            return res.status(400).json({message : "invalid password"});
        }
    } catch (error) {
        res.status(400).json({message : "error occured", error :error});
    }
})

// only logged-in users with access token will be allowd to access this api
app.post("/protected" ,verifyToken ,(req,res)=>{
    jwt.verify(req.token,process.env.ACCESS_TOKEN_SECRET,(err,authData)=>{  
        if(err){  
            res.status(400).json({message : "error occured", error :error});  
        }else{  
            res.status(200).json({  
                message: "Validated",  
                authData  
            });  
        }  
    });
})

// function to verify the received token
function verifyToken(req, res,next) {  
    const bearerHearder = req.headers['authorization'];  
    if(typeof bearerHearder != 'undefined'){  
        const bearer = bearerHearder.split(' '); 
        const bearerToken = bearer[1];  
        req.token = bearerToken;  
        next();  
    }else{  
      
        res.sendStatus(403);  
    }  
} 

app.listen(5000, ()=>{
    console.log("listening to port 5000");
})


   // const data = jwt.verify(token , process.env.ACCESS_TOKEN_SECRET)    
   
   /*
   const authentication1 = async(req,res,next)=>{
    try {
        const jwt = req.cookies;
        const data = await jwt.verify(jwt , process.env.ACCESS_TOKEN_SECRET);
        if(data){
            next();
        }else{
            res.send("access denied");
        }
    } catch (error) {
        res.send(error);
    }
}
   */