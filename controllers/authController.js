const db = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

exports.register = async (req, res) => {
    const { username, email, password } = req.body;
    try {
        // Check if password is already used by another account
        const checkSql = 'SELECT password FROM users';
        db.query(checkSql, async (err, results) => {
            if (err) return res.status(500).json({ message: 'Server error' });

            for (let user of results) {
                const match = await bcrypt.compare(password, user.password);
                if (match) {
                    return res.status(400).json({ message: 'Password already in use by another account' });
                }
            }

            // Password is unique, proceed to register
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
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Server error' });
        if (results.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ message: 'Invalid password' });
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET || 'secretkey', { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    });
};