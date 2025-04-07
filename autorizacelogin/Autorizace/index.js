const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();          //ps jsem trochu zmateny u pojmu / nevim jak udelat Odevzdejte s exportem databáze a bez složky node_modules asi chapu ze mam odendat node modules ale nejsem si jisty takze to tam radi necham
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

const db = new sqlite3.Database('./auth.db', (err) => {
    if (err) console.log(err);
    console.log('Database connected');
});

db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        auth_token TEXT
    )`);

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, 
        [username, hashedPassword],
        (err) => {
            if (err) return res.send('registration error');
            res.redirect('/login');
        });
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err) return res.send('login error');
        if (!user) return res.send('invalid credentials');

        const passwordCorrect = await bcrypt.compare(password, user.password);
        if (!passwordCorrect) return res.send('invalid credentials');

        const token = crypto.randomBytes(32).toString('hex');
        db.run(`UPDATE users SET auth_token = ? WHERE id = ?`, [token, user.id], (err) => {
            if (err) return res.send('error saving token');
            res.cookie('auth_token', token, { httpOnly: true });
            res.redirect('/user');
        });
    })
});

function authorize(req, res, next) {
    const token = req.cookies.auth_token;
    if (!token) return res.send('no token provided');

    db.get(`SELECT * FROM users WHERE auth_token = ?`, [token], (err, user) => {
        if (err) return res.send('auth error');
        if (!user) return res.send('invalid token');
        req.user = user;
        next();
    });
}

app.get('/user', authorize, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'user.html'));
});

app.get('/logout', (req, res) => {
    res.cookie('auth_token', '', { httpOnly: true });
    res.redirect('/login');
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
