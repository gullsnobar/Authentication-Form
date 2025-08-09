// app.js

const express = require('express');
const app = express();
const userModel = require('./models/user');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config(); 

// CONFIGURATION
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET || "default_secret_key";

// ===== MIDDLEWARE: AUTH CHECK =====
function isLoggedIn(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.redirect("/login");
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie("token");
        return res.redirect("/login");
    }
}

// ===== ROUTES =====
app.get('/', (req, res) => {
    res.render("index");
});

app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/signup', async (req, res) => {
    try {
        let { username, email, password, age } = req.body;

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        let createdUser = await userModel.create({
            username,
            email,
            password: hash,
            age
        });

        let token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "strict" });
        res.redirect("/dashboard");

    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/login', async (req, res) => {
    try {
        let user = await userModel.findOne({ email: req.body.email });
        if (!user) return res.status(400).send("Invalid credentials");

        const match = await bcrypt.compare(req.body.password, user.password);
        if (!match) return res.status(400).send("Invalid credentials");

        let token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "strict" });
        res.redirect("/dashboard");

    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});

app.get('/dashboard', isLoggedIn, (req, res) => {
    res.render("dashboard", { user: req.user });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect("/login");
});

// ===== START SERVER =====
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
