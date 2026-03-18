const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
// login and reegister
router.post('/register', authController.register);
router.post('/login', authController.login);

// User management routes
router.get('/users', authController.getUsers);
router.post('/users', authController.addUser);
router.put('/users/:id', authController.editUser);
router.delete('/users/:id', authController.deleteUser);

module.exports = router;
