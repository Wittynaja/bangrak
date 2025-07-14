"use strict";
//extension
require("dotenv").config();
const express = require("express");
const sanitizeHTML = require("sanitize-html");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const database = require("better-sqlite3");
const db = new database("mydb.sqlite");
db.pragma("journal_mode = WAL"); //make it faster
const app = express();

//db setup here
const createTables = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `
  ).run();

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users(id)
)`
  ).run();

  db.prepare(
    `
  CREATE TABLE IF NOT EXISTS history (
    visitedDate TEXT,
    places TEXT,
    parkingSpot INTEGER,
    spotLeft INTEGER,
    rating INTEGER,
    customerid INTEGER,
    FOREIGN KEY (customerid) REFERENCES users(id)
  )
  `
  ).run();
});

createTables();

//db setup end here

// Helper function to get user history
function getUserHistory(userId) {
  if (!userId) return [];
  const historyStatement = db.prepare(
    "SELECT * FROM history WHERE customerid = ? ORDER BY visitedDate DESC"
  );
  return historyStatement.all(userId);
}

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public")); // use css from 'public'
app.use(cookieParser());
app.use(function (req, res, next) {
  res.locals.errors = [];

  //try to decode incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user;
  next();
}); //middleware

// /= root of domain - MODIFIED TO SHOW LOGIN FIRST
// ejs = template engine
app.get("/", (req, res) => {
  console.log("Root route hit. User authenticated:", !!req.user);
  if (req.user) {
    console.log("User is logged in, redirecting to homepage");
    // If user is logged in, redirect to homepage
    return res.redirect("/homepage");
  }
  console.log("User not logged in, rendering login page");
  // If user is not logged in, show login page
  res.render("login", { errors: [], history: [] });
});

// NEW ROUTE: Dedicated homepage route for logged-in users
app.get("/homepage", (req, res) => {
  console.log("Homepage route hit. User authenticated:", !!req.user);
  if (req.user) {
    const history = getUserHistory(req.user.userid);
    console.log("Rendering homepage for user:", req.user.username);
    return res.render("homepage", { history });
  }
  console.log("User not authenticated, redirecting to login");
  // If not logged in, redirect to login
  res.redirect("/");
});

app.get("/park", (req, res) => {
  const history = getUserHistory(req.user ? req.user.userid : null);
  res.render("park", { history });
});

// MODIFIED: Login route now redirects to homepage after successful login
app.get("/login", (req, res) => {
  if (req.user) {
    // If already logged in, redirect to homepage
    return res.redirect("/homepage");
  }
  // Show login page with no errors initially
  res.render("login", { errors: [], history: [] });
});

app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp");
  res.redirect("/");
});

//receive the info after clicking the sign up button
//after receive action /register in the ejs page

//log in - MODIFIED TO REDIRECT TO HOMEPAGE AFTER LOGIN
app.post("/login", (req, res) => {
  let errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  //username must not empty
  if (req.body.username.trim() == "") errors = ["Invalid username or password"];
  if (req.body.password == "") errors = ["Invalid username or password"];

  if (errors.length) {
    return res.render("login", { errors, history: [] });
  }

  //check if there are username in db
  const userInQuestionStatement = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  );
  const userInQuestion = userInQuestionStatement.get(req.body.username);

  if (!userInQuestion) {
    errors = ["Invalid username or password"];
    return res.render("login", { errors, history: [] });
  }

  const matchOrNot = bcrypt.compareSync(
    req.body.password,
    userInQuestion.password
  ); // can be true or false
  if (!matchOrNot) {
    errors = ["Invalid username or password"];
    return res.render("login", { errors, history: [] });
  }

  //give them a cookie
  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: userInQuestion.id,
      username: userInQuestion.username,
    },
    process.env.JWTSECRET
  );
  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24, //cookie is good for 1 day
  });

  // Redirect to homepage after successful login
  res.redirect("/homepage");
});

function mustBeLoggedIn(req, res, next) {
  if (req.user) {
    return next();
  }
  return res.redirect("/");
}

app.get("/create-post", mustBeLoggedIn, (req, res) => {
  const history = getUserHistory(req.user.userid);
  res.render("create-post", { errors: [], history });
});

function sharedPostValidation(req) {
  const errors = [];
  if (typeof req.body.title !== "string") req.body.title = "";
  if (typeof req.body.body !== "string") req.body.body = "";
  //trim html tag npm install sanitize-html
  req.body.title = sanitizeHTML(req.body.title.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });
  req.body.body = sanitizeHTML(req.body.body.trim(), {
    allowedTags: [],
    allowedAttributes: {},
  });

  if (!req.body.title) errors.push("You must provide a title.");
  if (!req.body.body) errors.push("You must provide a content.");

  return errors;
}

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  const errors = sharedPostValidation(req);
  if (errors.length) {
    const history = getUserHistory(req.user.userid);
    return res.render("create-post", { errors, history });
  }

  //save to db
  const ourStatement = db.prepare(
    "INSERT INTO posts (title, body, authorid, createdDate) VALUES(?,?,?,?)"
  );
  const result = ourStatement.run(
    req.body.title,
    req.body.body,
    req.user.userid,
    new Date().toISOString()
  );

  const getPostStatement = db.prepare("SELECT * FROM posts WHERE id = ?");
  const realPost = getPostStatement.get(result.lastInsertRowid);

  res.redirect("/homepage");
});

app.get("/create-account", (req, res) => {
  const history = getUserHistory(req.user ? req.user.userid : null);
  res.render("create-account", { history });
});

//sign in - MODIFIED TO REDIRECT TO HOMEPAGE AFTER REGISTRATION
app.post("/register", (req, res) => {
  const errors = [];

  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push("U must provide a username");
  if (req.body.username && req.body.username.length < 3)
    errors.push("Username must be at least 3 characters.");
  if (req.body.username && req.body.username.length > 10)
    errors.push("Username can not exceed 10 characters.");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("Username can only contain numbers and letters");
  //check if username exist already
  const usernameStatement = db.prepare(
    "SELECT * FROM users WHERE username = ?"
  );
  const usernameCheck = usernameStatement.get(req.body.username);

  if (usernameCheck) errors.push("That username is already existed");

  if (!req.body.password) errors.push("U must provide a Password");
  if (req.body.password && req.body.password.length < 12)
    errors.push("Password must be at least 12 characters.");
  if (req.body.password && req.body.password.length > 70)
    errors.push("Password can not exceed 70 characters.");
  if (errors.length) {
    return res.render("login", { errors, history: [] });
  }

  // save the new user in DB (npm install better-sqlite3)
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  const ourStatement = db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  );
  const result = ourStatement.run(req.body.username, req.body.password);
  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const ourUser = lookupStatement.get(result.lastInsertRowid);
  //log the user in by giving them a cookie jwt.sign(a,b) b = secret value in .env, a = object
  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTSECRET
  );
  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24, //cookie is good for 1 day
  });

  res.redirect("/homepage");
});

app.post("/reserve", mustBeLoggedIn, (req, res) => {
  if (!req.body.park) {
    return res.status(400).send("no park data receive");
  }
  const customerid = req.user.userid;
  const [visitedPark, parkingSpot, spotLeft, rating] = req.body.park.split(",");
  const visitedDate = new Date().toISOString();

  const pushParkingInfo = db.prepare(
    "INSERT INTO history (visitedDate, places, parkingSpot, spotLeft, rating, customerid) VALUES(?,?,?,?,?,?)"
  );
  const result = pushParkingInfo.run(
    visitedDate,
    visitedPark,
    parkingSpot,
    spotLeft,
    rating,
    customerid
  );

  const history = getUserHistory(customerid);
  res.render("park", { history });
});

app.post("/navigate-to-home", (req, res) => {
  const history = getUserHistory(req.user ? req.user.userid : null);
  res.render("homepage", { history });
});

app.post("/navigate-to-reserve", (req, res) => {
  const history = getUserHistory(req.user ? req.user.userid : null);
  res.render("homepage", { history });
});

app.post("/view-history", mustBeLoggedIn, (req, res) => {
  const userId = req.user.userid;
  const history = getUserHistory(userId);
  res.render("homepage", { history });
});

app.post("/park", (req, res) => {
  const history = getUserHistory(req.user ? req.user.userid : null);
  res.render("homepage", { history });
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
