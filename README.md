# Room Planner

A platform for saving furniture and decor ideas and organizing them into rooms you're planning, before buying anything. CSC 4370 semester project by Mariam Kerzazi.

## Features so far
- User registration (username, e-mail, password) with salted, hashed passwords
- Login with success and error messages

## How to run
1. Install Node.js and MySQL.
2. Run `sql/setup.sql` in MySQL Workbench to create the database.
3. In this folder, run `npm install`.
4. Start the server: `ROOTPASS='your-mysql-password' node server.js`
5. Open http://localhost:3000/register.html
