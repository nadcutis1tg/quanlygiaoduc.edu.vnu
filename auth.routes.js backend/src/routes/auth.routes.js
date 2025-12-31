const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const passport = require('../config/passport');
const { verifyToken } = require('../middlewares/auth.middleware'); // Nếu có middleware

// ========== EMAIL/PASSWORD ==========
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.post('/refresh-token', authController.refreshToken);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// ========== GOOGLE OAUTH ==========
router.get('/google', passport.authenticate('google', { 
  scope: ['profile', 'email'],
  prompt: 'select_account'
}));

router.get('/google/callback', 
  passport.authenticate('google', { 
    session: false,
    failureRedirect: '/login?error=oauth_failed' // Redirect nếu fail
  }),
  authController.oauthCallback
);

// ========== APPLE OAUTH ==========
// LƯU Ý: Apple yêu cầu GET request cho initiation
router.get('/apple', passport.authenticate('apple', { 
  session: false,
  scope: ['name', 'email']
}));

router.post('/apple/callback', 
  passport.authenticate('apple', { 
    session: false,
    failureRedirect: '/login?error=apple_auth_failed'
  }),
  authController.oauthCallback
);

// ========== VERIFICATION & PROFILE ==========
router.get('/verify', verifyToken, authController.verifyToken);
router.get('/profile', verifyToken, authController.getProfile);
router.put('/profile', verifyToken, authController.updateProfile);

module.exports = router;
