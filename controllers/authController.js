const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();
const isStrongPassword = (password) => {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    return regex.test(password);
};

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


const isLegitEmail = (email) => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
};

// --- USER REGISTRATION ---
exports.register = async (req, res) => {
    const { username, email, password } = req.body;
    const captchaToken = req.body['g-recaptcha-response'];
    

    if (!username || !email || !password) {
        return res.status(400).json({ message: "All fields (Username, Email, Password) are required." });
    }

    // Email Format 
    if (!isLegitEmail(email)) {
        return res.status(400).json({ message: "Please enter a valid email format (e.g., user@example.com)." });
    }

    if (!captchaToken) return res.status(400).json({ message: "Please complete the CAPTCHA." });

    try {
        const verifyUrl = `https://www.google.com/recaptcha/api/siteverify`;
        const captchaVerify = await axios.post(verifyUrl, null, {
            params: { secret: process.env.RECAPTCHA_SECRET_KEY, response: captchaToken }
        });

        if (!captchaVerify.data.success) return res.status(400).json({ message: "CAPTCHA failed." });

if (!isStrongPassword(password)) {
        return res.status(400).json({ 
            message: "Password is too weak. Requirements: 8+ chars, 1 uppercase, 1 number, 1 special char." 
        });
    }


        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });
            if (results.length > 0) return res.status(400).json({ message: 'Email already registered' });

            const hashedPassword = await bcrypt.hash(password, 10);
            db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err) => {
                if (err) return res.status(500).json({ message: 'Error registering' });
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
};

// ---LOGIN --
exports.login = async (req, res) => {
    const { email, password } = req.body;

   
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    
    if (!isLegitEmail(email)) {
        return res.status(400).json({ message: "Invalid email format." });
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ message: 'Invalid password' });

        const token = jwt.sign(
            { id: user.id, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );
        
        res.json({ message: 'Login successful', token, role: user.role });
    });
};

// --- USER MANAGEMENTT ---
exports.getUsers = (req, res) => {
    db.query('SELECT id, username, email, created_at FROM users', (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        res.json(results);
    });
};

exports.addUser = async (req, res) => {
    const { username, email, password } = req.body;

    if (!isLegitEmail(email)) {
        return res.status(400).json({ message: "Invalid email format." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err) => {
        if (err) return res.status(500).json({ message: 'Error adding user' });
        res.status(201).json({ message: 'User added successfully' });
    });
};

exports.editUser = (req, res) => {
    const { username, email } = req.body;

    if (!isLegitEmail(email)) {
        return res.status(400).json({ message: "Invalid email format." });
    }

    db.query('UPDATE users SET username = ?, email = ? WHERE id = ?', [username, email, req.params.id], (err) => {
        if (err) return res.status(500).json({ message: 'Error updating' });
        res.json({ message: 'User updated' });
    });
};

exports.deleteUser = (req, res) => {
    db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ message: 'Error deleting' });
        res.json({ message: 'User deleted' });
    });
};

// --- GOOGLE LOGIN ---
exports.googleLogin = async (req, res) => {
    const { token } = req.body;
    try {
        const ticket = await client.verifyIdToken({ idToken: token, audience: process.env.GOOGLE_CLIENT_ID });
        const { email, name } = ticket.getPayload();
        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (results.length === 0) {
                db.query('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [name, email, 'google_authenticated']);
            }
            const appToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ message: 'Google login successful', token: appToken });
        });
    } catch (error) {
        res.status(400).json({ message: 'Invalid Google token' });
    }
};

// --- FORGOT PASSWORD ---
exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!isLegitEmail(email)) {
        return res.status(400).json({ message: "Invalid email format." });
    }

    db.query('SELECT username, password FROM users WHERE email = ?', [email], async (err, results) => {
        if (err || results.length === 0) return res.status(404).json({ message: "Email not found." });
        
        const user = results[0];
        if (user.password === 'google_authenticated') {
            return res.status(400).json({ isGoogleUser: true, message: "Use Google Login!" });
        }

        const token = crypto.randomBytes(32).toString('hex');
        const expiry = new Date(Date.now() + 3600000); 

        db.query('UPDATE users SET reset_token = ?, reset_expiry = ? WHERE email = ?', [token, expiry, email], async (err) => {
            if (err) return res.status(500).json({ message: "Failed to generate link." });

            const resetUrl = `http://localhost:3000/reset-password.html?token=${token}`;
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset Request',
                html: `
                    <p>Hi ${user.username},</p>
                    <p>You requested a password reset. Click the link below to set a new password:</p>
                    <a href="${resetUrl}">${resetUrl}</a>
                    <p>This link will expire in 1 hour.</p>
                `
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.log(error);
                    return res.status(500).json({ message: "Error sending email." });
                }
                res.json({ message: "Reset link sent to your Gmail!" });
            });
        });
    });
};

// --- RESET PASSWORD ---
exports.resetPassword = async (req, res) => {
    const { token, password } = req.body;
    db.query('SELECT id FROM users WHERE reset_token = ? AND reset_expiry > NOW()', [token], async (err, results) => {
        if (err || results.length === 0) return res.status(400).json({ message: "Invalid link." });

        const hashedPassword = await bcrypt.hash(password, 10);
        db.query('UPDATE users SET password = ?, reset_token = NULL, reset_expiry = NULL WHERE id = ?', [hashedPassword, results[0].id], (err) => {
            if (err) return res.status(500).json({ message: "Error updating." });
            res.json({ message: "Password updated!" });
        });
    });
};