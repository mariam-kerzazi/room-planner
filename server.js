// ---------- PACKAGES ----------
const express = require("express");               // web server framework
const crypt = require("crypto");                  // built-in Node module used to hash passwords
const session = require("express-session");       // stores session data so users stay logged in
const cookieParser = require("cookie-parser");    // reads cookies sent by the browser
const mysql = require("mysql2");                  // connects to the MySQL database

const app = express();

// ---------- MIDDLEWARE ----------
app.use(express.urlencoded({ extended: true }));  // lets us read form data from req.body
app.use(express.static("public"));                // serves register.html, login.html, style.css
app.use(cookieParser());                          // reads cookies so the session ID can be found

// Session setup: the browser keeps a cookie with a session ID,
// and the server uses that ID to look up who is logged in.
app.use(session({
	// Secret used to sign the session cookie. Set SESSION_SECRET when starting the server;
	// the fallback is only for testing on your own computer.
	secret: process.env.SESSION_SECRET || "roomplanner-dev-secret",
	resave: false,              // don't save the session again if nothing changed
	saveUninitialized: false,   // don't create a session until someone logs in
	cookie: {
		maxAge: 60000 * 60,     // session lasts 1 hour (in milliseconds)
		httpOnly: true,         // browser JavaScript can't read the cookie (helps prevent XSS)
		secure: false           // set to true if the site is served over HTTPS
	}
}));

// ---------- DATABASE CONNECTION ----------
// The MySQL password comes from the ROOTPASS environment variable so it is never saved in the code
const pass = process.env.ROOTPASS;
const conn = mysql.createConnection({host:"localhost",user:"root",password:pass,database:"roomplanner",port:3306});

conn.connect(function(err)
{
	if(err)
		console.log("Couldnt connect to MySQL",err);
	else
		console.log("Database connection established");
});

// ---------- HELPER FUNCTIONS ----------

// Password hashing settings (same as the class sample)
const hashRounds = 100;
const hashLength = 64;

// Hashes a password with the given salt
function hashPassword(plainPass, salt)
{
	return crypt.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, 'sha512').toString('hex');
}

// Makes user-entered text safe to put in a web page,
// so a username like <script> can't run code in the browser
function escapeHtml(text)
{
	return String(text)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

// Wraps a message in a full page that uses the site's styling
// type is "success" or "error", which changes the heading color
function page(type, heading, body)
{
	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>${heading}</title>
	<link href="https://fonts.googleapis.com/css2?family=Alfa+Slab+One&family=Poppins:wght@400;600&display=swap" rel="stylesheet">
	<link rel="stylesheet" href="style.css">
</head>
<body>
	<main class="card message ${type}">
		<h1>${heading}</h1>
		<p>${body}</p>
	</main>
</body>
</html>`;
}

// ---------- REGISTER ----------
// Receives the form from register.html and saves the new user
app.post("/register", function(req,res)
{
	let username = req.body.username;
	let email = req.body.email;
	let plainPass = req.body.password;

	// Every user gets their own random salt, so two users with the same
	// password still end up with different hashes
	let salt = crypt.randomBytes(16).toString('hex');
	let hashedPass = hashPassword(plainPass, salt);

	// ? placeholders keep user input from being run as SQL (prevents SQL injection)
	let sql = "insert into users (username,email,password,salt) values (?,?,?,?)";
	conn.query(sql, [username,email,hashedPass,salt], function(err,result)
	{
		if (err)
		{
			console.log("There was an error registering a user", err);
			// ER_DUP_ENTRY means the username or email already exists (both are UNIQUE)
			if (err.code === "ER_DUP_ENTRY")
				res.send(page("error", "Already taken",
					'That username or e-mail is already registered. <a href="register.html">Try again</a> or <a href="login.html">log in</a>.'));
			else
				res.send(page("error", "Registration failed",
					'Something went wrong on our end. <a href="register.html">Try again</a>.'));
		}
		else
			res.send(page("success", "You're in!",
				'You have successfully registered. <a href="login.html">Log in here</a>.'));
	});
});

// ---------- LOGIN ----------
// Receives the form from login.html, checks the password,
// and saves the user in the session if it's correct
app.post("/login", function(req,res)
{
	let username = req.body.username;
	let plainPass = req.body.password;

	// Look up the user first so can get their own salt
	let sql = "select * from users where username = ?";
	conn.query(sql, [username], function(err,result)
	{
		if (err)
		{
			console.log("There was an error logging in", err);
			res.send(page("error", "Login failed",
				'Something went wrong on our end. <a href="login.html">Back to login</a>.'));
			return;
		}

		// Hash the password they typed with the stored salt and compare
		let loggedIn = false;
		if (result.length > 0)
		{
			let user = result[0];
			loggedIn = hashPassword(plainPass, user.salt) === user.password;
		}

		if (loggedIn)
		{
			// SESSION: store the logged-in user's info in the session.
			// This is what lets other pages (like /profile) know who is logged in.
			// The password and salt are NOT stored in the session.
			req.session.user = {
				user_id: result[0].user_id,
				username: result[0].username,
				email: result[0].email
			};

			res.send(page("success", "Welcome back",
				'You have logged in successfully. Visit your <a href="/profile">profile</a>.'));
		}
		else
			res.send(page("error", "Login failed",
				'The login credentials were incorrect. <a href="login.html">Back to login</a>.'));
	});
});

// ---------- PROFILE ----------
// Shows the logged-in user's username, read from the session
app.get("/profile", function(req,res)
{
	// No user in the session means nobody is logged in
	if (!req.session.user)
	{
		res.send(page("error", "Not logged in",
			'You need to log in to see your profile. <a href="login.html">Log in here</a>.'));
		return;
	}

	// Read the user's info that was saved in the session during login
	let username = escapeHtml(req.session.user.username);
	let email = escapeHtml(req.session.user.email);

	res.send(page("success", `Hi, ${username}`,
		`You're logged in as <strong>${username}</strong> (${email}).<br>
		Your saved rooms and items will show up here.<br><br>
		<a href="/logout">Log out</a>`));
});

// ---------- LOGOUT ----------
// Destroys the session so the user is no longer logged in
app.get("/logout", function(req,res)
{
	req.session.destroy(function(err)
	{
		if (err)
		{
			console.log("There was an error logging out", err);
			res.send(page("error", "Logout failed",
				'Something went wrong. <a href="/profile">Back to profile</a>.'));
		}
		else
		{
			// Also remove the session cookie from the browser
			// ("connect.sid" is express-session's default cookie name)
			res.clearCookie("connect.sid");
			res.send(page("success", "Logged out",
				'You have logged out successfully. <a href="login.html">Log in again</a>.'));
		}
	});
});

// ---------- SHUTDOWN ----------
// Close the database connection cleanly when the server is stopped (Ctrl + C)
process.on("SIGINT", function()
{
	conn.end(function(err)
	{
		if (err)
			console.log("Error closing the database connection", err);
		else
			console.log("Database connection closed");
		process.exit();
	});
});

// ---------- START SERVER ----------
app.listen(3000, function()
{
	console.log("Server running at http://localhost:3000/login.html");
});
