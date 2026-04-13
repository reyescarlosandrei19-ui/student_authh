const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

// Existing routes
router.post('/register', authController.register);
router.post('/login', authController.login);

// User management 
router.get('/users', authController.getUsers);
router.post('/users', authController.addUser);
router.put('/users/:id', authController.editUser);
router.delete('/users/:id', authController.deleteUser);


router.post('/google', authController.googleLogin);

router.post('/forgot-password', authController.forgotPassword);

router.post('/reset-password', authController.resetPassword);
module.exports = router; 

