//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook");
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));


app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', true);
// let URI = "mongodb+srv://ufaq302:khan12345@cluster0.1mekptf.mongodb.net/?retryWrites=true&w=majority/test"
let URI = "mongodb://127.0.0.1:27017/userDB"
mongoose.connect(URI);
// mongodb+srv://ufaq302:<password>@cluster0.1mekptf.mongodb.net/?retryWrites=true&w=majority

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

//SERIALIZE AND DESERILIAZE USER
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});


// Google Auth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    // callbackURL: "https://secrets-app-mn1w.onrender.com/auth/google/secrets",
    callbackURL: "https://secrets-app-mn1w.onrender.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile)
        User.findOrCreate({ googleId: profile.id },
            function (err, user) {
                return cb(err, user);
            });
    }
));

app.get("/auth/google", passport.authenticate("google", { scope: ['profile'] }),
    function (req, res) {
        console.log("Successfully Moved to Google Auth");
    }
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }), function (req, res) {
        console.log("Successfully Authenticated Through Google");
        res.redirect("/secrets");
    }
);

//Facebook Auth
passport.use(new FacebookStrategy({
    clientID: process.env.FB_ID,
    clientSecret: process.env.FB_SECRET,
    // callbackURL: "https://secrets-app-mn1w.onrender.com/auth/facebook/secrets"
    callbackURL: "https://secrets-app-mn1w.onrender.com/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile)

        User.findOrCreate({ facebookId: profile.id },
            function (err, user) {
                console.log("Facebook Auth Processed");
                return cb(err, user);
            });
    }
));

app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });



app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);;
        } else {
            res.redirect('/');
        }
    })
});

app.post("/register", function (req, res) {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/login", function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("secrets")
            });
        }
    });
});


// app.post("/register", function (req, res) {
//     bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         newUser.save(function (err) {
//             if (err) {
//                 console.log(err);
//             } else {
//                 res.render("secrets");
//             }
//         });
//     });
// });

// app.post("/login", function (req, res) {
//     const username = req.body.username;
//     const password = req.body.password;

//     User.findOne({ email: username }, function (err, foundUser) {
//         if (err) {
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 bcrypt.compare(password, foundUser.password, function (err, result) {
//                     if (result === true) {
//                         res.render("secrets");
//                     }
//                 });
//             }
//         }
//     });
// });




app.listen(3000, function () {
    console.log("Started on Port: 3000");
})