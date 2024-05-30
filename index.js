"use strict";
require("dotenv").config()
const express = require("express");
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');
const nocache = require('nocache');
//const userModel = require('./Db/Schema/user1');
const { v4: uuidv4 } = require('uuid');
const { consts } = require('./Enums/consts');
const { limiter, apiLimiter, loginLimiter, registerLimiter } = require('./Utilities/limiters');

//const { connectToDb } = require('./Db/mongo1');
const Database = require("./Db/mongo2");
const isEmpty = require('./Utilities/isEmpty');
const { getEnv, getMongoUri } = require('./Utilities/getEnv');

const mongoUri = getMongoUri()
const environment = getEnv()

const app = express();

app.set('view engine', 'ejs');
app.set('views', 'Ejsviews');

app.set('trust proxy', 1) // trust first proxy used for session management under a2hosting

app.use(cors({
    origin: consts.origin,
    methods: consts.allowedMethods,
    credentials: true
}))

// landing page nonce is made available for non-dashboard requests.
// dashboard requests will have a seperate nonce
const landingPageNonce = crypto.randomBytes(16).toString("hex");

/*
{
      directives: {
        "script-src": ["'self'", consts.origin],
      }
}
*/
app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        "default-src": [
            "'self'"
        ],
        "script-src": [
            "'self'",
            "https://cdnjs.cloudflare.com"
        ],
        "script-src-attr": [
            "'self'",
            "'unsafe-inline'"
        ],
        "style-src": [
            "'self'",
            "https://cdnjs.cloudflare.com",
            "https://fonts.googleapis.com",
            "'unsafe-inline'"
        ],
      },
},
    xDownloadOptions: false,
  }));
app.use(nocache());

// puts content-type: application/json into req.body with a size limit
app.use(express.json({ limit: '6mb' }));
// do not allow html content-type: x-www-form-urlencoded POST into req.body so set extended to false...if set to true limit applies
app.use(express.urlencoded({ extended: false, limit: '6mb' }))

let dbError = false
let dbMessage = ''

app.use(cookieParser())

app.use((req, res, next) => {
    res.append('Access-Control-Expose-Headers','Authorization')
    if (!isEmpty(req.session) && !isEmpty(req.session.jwt)) {
        req.headers.authorization = 'Bearer ' + req.session.jwt;
    }
    next()
})

app.get("/", limiter, (req, res) => {
    const options = {
        maxAge: consts.min15, // would expire after 15 minutes
        httpOnly: true, // The cookie only accessible by the web server
        secure: true,
        sameSite: true
    }

    res.cookie('XSRF-TOKEN', landingPageNonce, options);
    
    // render main landing page
    return res.render('index2', { dbError: dbError ? dbMessage : `${environment}`, landingPageNonce, DOMAIN: process.env.DOMAIN });
});

// using express-session
// if after app.get("/") but before the other routes then a session cookie 
// will not be created which will increase the speed of loading the 
// landing page and save on time to save the session to the DB.  This helps
// prevent resource from being taken if a DOS attach takes place.
app.use(session({
    secret: consts.secret,
    name: 'sessionId',
    resave: false,
    cookie: { 
        maxAge: consts.expiresMilli,
        secure: true,  // must be https (secure)
        httpOnly: true,
        sameSite: 'strict'  // only same domain can access the site
    },
    saveUninitialized: true,  // true means to save to a DB (store)
    store: MongoStore.create({ 
        mongoUrl: mongoUri,
        collectionName: 'sessions'
    })
}));

const dashboardRouter = require('./Routes/dashboard')
app.use('/dashboard', dashboardRouter)

const loginRouter = require('./Routes/login')
app.use('/login', loginRouter)

// add in logging
app.get('/logout', limiter, async (req, res) => {
    req.session.destroy()
    return res.redirect('/')
})

const resetPasswordRouter = require('./Routes/resetpassword')
app.get('/resetpassword', resetPasswordRouter)
app.post('/resetpassword/update', resetPasswordRouter)
app.post('/resetpassword/changepassword', resetPasswordRouter)

app.get('/*', limiter, (req, res) => {
    req.session.destroy()
    res.status(404).send("Sorry...Page is not foundkk.")
})

app.listen();
