const express = require('express');
const app = express();
const userModel = require('./models/user');
const bcrypt = require('bcryptjs'); 
const cookieParser = require('cookie-parser');
const path = require('path');
const jwt = require('jsonwebtoken');

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

const JWT_SECRET = "shsfhqwugdgqdnjeq"; 

app.get('/', (req, res) => {
    res.render("index");
});

app.post('/create', async (req, res) => {
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

        let token = jwt.sign({ email }, JWT_SECRET);
        res.cookie("token", token);
        res.send(createdUser);
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});

app.post('/login', async function (req, res) {
    try {
        let user = await userModel.findOne({ email: req.body.email });
        if (!user) return res.status(400).send("User not found");

        bcrypt.compare(req.body.password, user.password, function (err, result) {
            if (result) {
                let token = jwt.sign({ email: user.email }, JWT_SECRET);
                res.cookie("token", token);
                res.send("Login successful");
            } else {
                res.status(401).send("Invalid password");
            }
        });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});

app.get('/logout', function (req, res) {
    res.cookie('token', "");
    res.redirect("/");
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
