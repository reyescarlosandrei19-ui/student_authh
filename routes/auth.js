const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authorize } = require('../middleware/roleMiddleware');

// Existing routes
router.post('/register', authController.register);
router.post('/login', authController.login);

router.get('/users', authorize(['admin']), authController.getUsers);
router.delete('/users/:id', authorize(['admin']), authController.deleteUser);

// User management 
router.get('/users', authController.getUsers);
router.post('/users', authController.addUser);
router.put('/users/:id', authController.editUser);
router.delete('/users/:id', authController.deleteUser);


router.post('/google', authController.googleLogin);

router.post('/forgot-password', authController.forgotPassword);

router.post('/reset-password', authController.resetPassword);
module.exports = router; 

