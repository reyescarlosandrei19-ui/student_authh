const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const axios = require('axios'); // Required for CAPTCHA verification
require('dotenv').config();

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const loginAttempts = {};

// --- USER REGISTRATION (Merged with CAPTCHA) ---
exports.register = async (req, res) => {
    const { username, email, password } = req.body;
    const captchaToken = req.body['g-recaptcha-response'];

    // 1. Check if CAPTCHA was attempted
    if (!captchaToken) {
        return res.status(400).json({ message: "Please complete the CAPTCHA." });
    }

    try {
        // 2. Verify Token with Google
        const verifyUrl = `https://www.google.com/recaptcha/api/siteverify`;
        const captchaVerify = await axios.post(verifyUrl, null, {
            params: {
                secret: process.env.RECAPTCHA_SECRET_KEY,
                response: captchaToken
            }
        });

        if (!captchaVerify.data.success) {
            return res.status(400).json({ message: "CAPTCHA verification failed. Try again." });
        }

        // 3. Proceed with existing SQL Registration logic
        const checkSql = 'SELECT * FROM users WHERE email = ?';
        db.query(checkSql, [email], async (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            
            if (results.length > 0) {
                return res.status(400).json({ message: 'Email already registered' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
            db.query(sql, [username, email, hashedPassword], (err, result) => {
                if (err) return res.status(500).json({ message: 'Error registering user', error: err });
                res.status(201).json({ message: 'User registered successfully' });
            });
        });

    } catch (error) {
        console.error("CAPTCHA Error:", error);
        res.status(500).json({ message: "Internal Server Error during verification." });
    }
};

// --- STANDARD LOGIN ---
exports.login = async (req, res) => {
    const { email, password } = req.body;

    if (loginAttempts[email]) {
        const { attempts, lockUntil } = loginAttempts[email];
        if (lockUntil && Date.now() < lockUntil) {
            const secondsLeft = Math.ceil((lockUntil - Date.now()) / 1000);
            return res.status(429).json({ message: `Too many failed attempts. Try again in ${secondsLeft} seconds.` });
        }
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            if (!loginAttempts[email]) loginAttempts[email] = { attempts: 0, lockUntil: null };
            loginAttempts[email].attempts += 1;
            if (loginAttempts[email].attempts >= 3) {
                loginAttempts[email].lockUntil = Date.now() + 30 * 1000;
                return res.status(429).json({ message: 'Too many failed attempts. Try again in 30 seconds.' });
            }
            return res.status(401).json({ message: `Invalid password.` });
        }

        loginAttempts[email] = { attempts: 0, lockUntil: null };
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
};

// --- USER MANAGEMENT ---
exports.getUsers = (req, res) => {
    const sql = 'SELECT id, username, email, created_at FROM users';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        res.json(results);
    });
};

exports.addUser = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
        db.query(sql, [username, email, hashedPassword], (err, result) => {
            if (err) return res.status(500).json({ message: 'Error adding user', error: err });
            res.status(201).json({ message: 'User added successfully' });
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

exports.editUser = async (req, res) => {
    const { username, email } = req.body;
    const { id } = req.params;
    const sql = 'UPDATE users SET username = ?, email = ? WHERE id = ?';
    db.query(sql, [username, email, id], (err, result) => {
        if (err) return res.status(500).json({ message: 'Error updating user', error: err });
        res.json({ message: 'User updated successfully' });
    });
};

exports.deleteUser = (req, res) => {
    const { id } = req.params;
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ message: 'Error deleting user', error: err });
        res.json({ message: 'User deleted successfully' });
    });
};

// --- GOOGLE OAUTH LOGIN ---
exports.googleLogin = async (req, res) => {
    const { token } = req.body;
    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const { email, name, picture } = ticket.getPayload();

        const checkUserSql = 'SELECT * FROM users WHERE email = ?';
        db.query(checkUserSql, [email], async (err, results) => {
            if (err) console.error("Database error:", err);
            if (results.length === 0) {
                const insertSql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
                db.query(insertSql, [name, email, 'google_authenticated'], (err, result) => {
                    if (err) console.error("Error saving new Google user:", err);
                    else console.log("New Google user saved!");
                });
            }
        });

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Login Security Alert',
            html: `<h2>Hello ${name},</h2><p>Successful login via Google.</p>`
        };

        await transporter.sendMail(mailOptions);

        const appToken = jwt.sign(
            { email: email, name: name }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        res.status(200).json({ 
            message: 'Google login successful', 
            token: appToken,
            user: { name, email, picture }
        });

    } catch (error) {
        console.error('Google Auth Error:', error);
        res.status(400).json({ message: 'Invalid Google token' });
    }
};