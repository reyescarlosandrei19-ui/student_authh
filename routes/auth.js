const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Existing routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// User management routes
router.get('/users', authController.getUsers);
router.post('/users', authController.addUser);
router.put('/users/:id', authController.editUser);
router.delete('/users/:id', authController.deleteUser);

// Move this ABOVE the module.exports
router.post('/google', authController.googleLogin);

module.exports = router; // This must always be the last line