const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const loginAttempts = {};

exports.register = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const checkSql = 'SELECT password FROM users';
        db.query(checkSql, async (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });

            for (let user of results) {
                const match = await bcrypt.compare(password, user.password);
                if (match) {
                    return res.status(400).json({ message: 'Password already in use by another account' });
                }
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
            db.query(sql, [username, email, hashedPassword], (err, result) => {
                if (err) return res.status(500).json({ message: 'Error registering user', error: err });
                res.status(201).json({ message: 'User registered successfully' });
            });
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;

    if (loginAttempts[email]) {
        const { attempts, lockUntil } = loginAttempts[email];
        if (lockUntil && Date.now() < lockUntil) {
            const secondsLeft = Math.ceil((lockUntil - Date.now()) / 1000);
            return res.status(429).json({ message: `Too many failed attempts. Try again in ${secondsLeft} seconds.` });
        }
        if (lockUntil && Date.now() >= lockUntil) {
            loginAttempts[email] = { attempts: 0, lockUntil: null };
        }
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            if (!loginAttempts[email]) {
                loginAttempts[email] = { attempts: 0, lockUntil: null };
            }
            loginAttempts[email].attempts += 1;
            if (loginAttempts[email].attempts >= 3) {
                loginAttempts[email].lockUntil = Date.now() + 30 * 1000;
                return res.status(429).json({ message: 'Too many failed attempts. Try again in 30 seconds.' });
            }
            const remaining = 3 - loginAttempts[email].attempts;
            return res.status(401).json({ message: `Invalid password. ${remaining} attempt(s) remaining.` });
        }

        loginAttempts[email] = { attempts: 0, lockUntil: null };
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
};

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