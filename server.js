const express = require("express");
const crypt = require("crypto");
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));   // serves register.html, login.html, style.css

const mysql = require("mysql2");
const pass = process.env.ROOTPASS;
const conn = mysql.createConnection({host:"localhost",user:"root",password:pass,database:"roomplanner",port:3306});

const hashRounds = 100;
const hashLength = 64;

conn.connect(function(err)
{
	if(err)
		console.log("Couldnt connect to MySQL",err);
	else
		console.log("Database connection established");
});

// Hash a password with a given salt (same settings as the class sample)
function hashPassword(plainPass, salt)
{
	return crypt.pbkdf2Sync(plainPass, salt, hashRounds, hashLength, 'sha512').toString('hex');
}

// Wraps a message in a page that uses the site's styling
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
app.post("/register", function(req,res)
{
	let username = req.body.username;
	let email = req.body.email;
	let plainPass = req.body.password;

	// Every user gets their own random salt
	let salt = crypt.randomBytes(16).toString('hex');
	let hashedPass = hashPassword(plainPass, salt);

	let sql = "insert into users (username,email,password,salt) values (?,?,?,?)";
	conn.query(sql, [username,email,hashedPass,salt], function(err,result)
	{
		if (err)
		{
			console.log("There was an error registering a user", err);
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
app.post("/login", function(req,res)
{
	let username = req.body.username;
	let plainPass = req.body.password;

	// Look up the user first so we can get THEIR salt
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

		let loggedIn = false;
		if (result.length > 0)
		{
			let user = result[0];
			loggedIn = hashPassword(plainPass, user.salt) === user.password;
		}

		if (loggedIn)
			res.send(page("success", "Welcome back",
				'You have logged in successfully.'));
		else
			res.send(page("error", "Login failed",
				'The login credentials were incorrect. <a href="login.html">Back to login</a>.'));
	});
});

app.listen(3000, function()
{
	console.log("Server running at http://localhost:3000/register.html");
});