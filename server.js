import express from "express"; 
import bodyParser from "body-parser";
import pg from "pg";  
import ejs from "ejs";
import bcrypt from "bcrypt";
import env from "dotenv"; 
import passport from "passport"; 
import session from "express-session";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";


const app = express(); 
const port = 3000;
env.config(); 
const saltRounds = 10;

app.use(
  session({ 
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: true,
  })
);

// the code below is used to initilze passport and express-sessions
app.use(passport.initialize());
app.use(passport.session());
// initilization of pasport and express-sessions closed

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static("public"));


const db = new pg.Client({
    user: process.env.THE_USER,
    host: "localhost",
    database: process.env.THE_DATABASE_NAME,
    password: process.env.PG_PASSWORD,
    port: 5432,
  });
  db.connect()


  app.get("/", (req, res) => {
    res.render("homePage.ejs")
  });

  
  app.get("/register", (req, res) => {
    res.render("register.ejs")
  })


  app.get("/login", (req, res) => {
    res.render("login.ejs")
  })

  // app.get for the google authentication route
  app.get('/mainPage', (req, res) => {
    if (req.isAuthenticated()) {
      res.render('mainPage.ejs');
    } else {
      res.redirect('/login');
    }
  });
  

  app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));

app.get( '/auth/google/mainPage',
    passport.authenticate( 'google', {
        successRedirect: '/mainPage',
        failureRedirect: '/login',
})
);

app.post(
  "/login",
    passport.authenticate("local", {
    successRedirect: "/mainPage",
    failureRedirect: "/login",
  })
);
  // google get route closed

app.post("/register", async (req, res) => { 
  const name = req.body.username; 
  const email = req.body.email;
  const password = req.body.password;

  try { 
    const checkResult = await db.query ("SELECT * FROM userstable WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) { 
      res.send("Email already exists. Try logging in this time")
    } else { 
      const overallResult = await db.query(
        "INSERT INTO userstable (name, email, password) VALUES ($1, $2, $3)",
        [name, email, password]
      );
      console.log(overallResult);
      res.render("mainPage.ejs")
    }
  } catch (err) { 
    console.log(err);
  }
})


app.post("/login", async (req, res) => { 
  
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  try { 
    const checkResult = await db.query ("SELECT * FROM userstable WHERE email = $1", [
      email,
    ]);
    if (checkResult.rows.length > 0) { 
      const user = checkResult.rows[0]; 
      const storedPassword = user.password;

      if (password === storedPassword) { 
        res.render("mainPage.ejs"); 
      } else { 
        res.send("Incorrect Password")
      }
    } else { 
      res.send("User not found"); 
    }
  } catch (err) { 
    console.log(err)
  }
})


passport.use( 
  new GoogleStrategy ( 
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/mainPage", 
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // console.log(profile);
        const result = await db.query("SELECT * FROM userstable WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO userstable (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err)
      }
    }
  )
);
// 
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});



app.listen(port, () => {
    console.log(`Server running on http://localhost/${port}`);
  });