const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../database/db');
const emailService = require('../services/email.service');
const { validationResult } = require('express-validator');
const logger = require('../utils/logger');

class AuthController {
  /**
   * Đăng ký tài khoản mới
   */
  async register(req, res) {
    const transaction = await db.connect();
    
    try {
      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      
      const { fullName, email, password, role = 'student' } = req.body;
      
      await transaction.query('BEGIN');
      
      // Kiểm tra email tồn tại
      const existingUser = await transaction.query(
        'SELECT id FROM users WHERE email = $1 FOR UPDATE',
        [email]
      );
      
      if (existingUser.rows.length > 0) {
        await transaction.query('ROLLBACK');
        logger.warn(`Registration attempt with existing email: ${email}`);
        return res.status(409).json({ 
          error: 'Email đã được đăng ký. Vui lòng sử dụng email khác hoặc đăng nhập.' 
        });
      }
      
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);
      
      // Tạo user
      const result = await transaction.query(
        `INSERT INTO users (full_name, email, password, role, login_method, email_verified) 
         VALUES ($1, $2, $3, $4, 'email', false) 
         RETURNING id, full_name, email, role, created_at`,
        [fullName, email, hashedPassword, role]
      );
      
      const user = result.rows[0];
      
      // Tạo email verification token
      const verificationToken = jwt.sign(
        { userId: user.id, type: 'email_verification' },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      
      // Lưu verification token
      await transaction.query(
        'UPDATE users SET verification_token = $1 WHERE id = $2',
        [verificationToken, user.id]
      );
      
      // Tạo JWT token cho đăng nhập tự động
      const authToken = jwt.sign(
        { 
          userId: user.id, 
          role: user.role,
          email: user.email 
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRE,
          issuer: 'quanlygiaoduc.edu.vnu',
          audience: 'web-client'
        }
      );
      
      await transaction.query('COMMIT');
      
      // Gửi email xác thực
      try {
        await emailService.sendWelcomeEmail(user.email, user.full_name, verificationToken);
      } catch (emailError) {
        logger.error(`Failed to send welcome email: ${emailError.message}`, { userId: user.id });
      }
      
      // Log
      logger.info(`User registered: ${user.email}`, {
        userId: user.id,
        role: user.role,
        ip: req.ip
      });
      
      // Response
      res.status(201).json({
        success: true,
        message: 'Đăng ký thành công. Vui lòng kiểm tra email để xác thực tài khoản.',
        data: {
          user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email,
            role: user.role,
            emailVerified: false,
            createdAt: user.created_at
          },
          token: authToken
        }
      });
      
    } catch (error) {
      await transaction.query('ROLLBACK');
      
      logger.error(`Registration error: ${error.message}`, {
        email: req.body.email,
        ip: req.ip,
        stack: error.stack
      });
      
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi trong quá trình đăng ký. Vui lòng thử lại sau.'
      });
    } finally {
      transaction.release();
    }
  }

  /**
   * Đăng nhập
   */
  async login(req, res) {
    try {
      // Validate input
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }
      
      const { email, password } = req.body;
      
      // Log login attempt
      logger.info(`Login attempt: ${email}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      // Tìm user
      const result = await db.query(
        `SELECT id, full_name, email, password, role, email_verified, 
                login_attempts, locked_until 
         FROM users WHERE email = $1`,
        [email]
      );
      
      if (result.rows.length === 0) {
        // Trả về thông báo chung để tránh user enumeration
        await new Promise(resolve => setTimeout(resolve, 1000)); // Delay để tránh timing attack
        return res.status(401).json({
          success: false,
          error: 'Email hoặc mật khẩu không đúng'
        });
      }
      
      const user = result.rows[0];
      
      // Kiểm tra tài khoản bị khóa
      if (user.locked_until && user.locked_until > new Date()) {
        return res.status(423).json({
          success: false,
          error: `Tài khoản tạm thời bị khóa. Vui lòng thử lại sau ${Math.ceil((user.locked_until - new Date()) / 60000)} phút.`
        });
      }
      
      // Xác thực password
      const isValidPassword = await bcrypt.compare(password, user.password);
      
      if (!isValidPassword) {
        // Tăng số lần đăng nhập thất bại
        const newAttempts = user.login_attempts + 1;
        let lockUntil = null;
        
        if (newAttempts >= 5) {
          lockUntil = new Date(Date.now() + 30 * 60000); // Khóa 30 phút
        }
        
        await db.query(
          'UPDATE users SET login_attempts = $1, locked_until = $2 WHERE id = $3',
          [newAttempts, lockUntil, user.id]
        );
        
        logger.warn(`Failed login attempt: ${email}`, {
          userId: user.id,
          attempts: newAttempts,
          ip: req.ip
        });
        
        return res.status(401).json({
          success: false,
          error: 'Email hoặc mật khẩu không đúng',
          remainingAttempts: 5 - newAttempts
        });
      }
      
      // Reset login attempts sau khi đăng nhập thành công
      await db.query(
        'UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = $1',
        [user.id]
      );
      
      // Tạo JWT token
      const token = jwt.sign(
        { 
          userId: user.id, 
          role: user.role,
          email: user.email,
          verified: user.email_verified
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRE,
          issuer: 'quanlygiaoduc.edu.vnu',
          audience: 'web-client'
        }
      );
      
      // Log successful login
      logger.info(`Successful login: ${user.email}`, {
        userId: user.id,
        role: user.role,
        ip: req.ip
      });
      
      // Response
      res.json({
        success: true,
        data: {
          user: {
            id: user.id,
            fullName: user.full_name,
            email: user.email,
            role: user.role,
            emailVerified: user.email_verified,
            lastLogin: user.last_login
          },
          token
        }
      });
      
    } catch (error) {
      logger.error(`Login error: ${error.message}`, {
        email: req.body.email,
        ip: req.ip,
        stack: error.stack
      });
      
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi trong quá trình đăng nhập'
      });
    }
  }

  /**
   * OAuth Callback
   */
  async oauthCallback(req, res) {
    try {
      if (!req.user) {
        logger.error('OAuth callback failed: No user in request');
        return res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
      }
      
      const user = req.user;
      
      // Tạo token
      const token = jwt.sign(
        { 
          userId: user.id, 
          role: user.role,
          email: user.email,
          verified: true 
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRE,
          issuer: 'quanlygiaoduc.edu.vnu'
        }
      );
      
      // Set HTTP-only cookie (an toàn hơn)
      res.cookie('auth_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
        domain: process.env.NODE_ENV === 'production' ? '.edu.vnu' : undefined
      });
      
      // Redirect với token trong session (tùy chọn)
      req.session.authToken = token;
      
      logger.info(`OAuth login successful: ${user.email}`, {
        userId: user.id,
        provider: req.query.provider || 'unknown'
      });
      
      // Redirect về frontend
      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?success=true`);
      
    } catch (error) {
      logger.error(`OAuth callback error: ${error.message}`, {
        stack: error.stack
      });
      res.redirect(`${process.env.FRONTEND_URL}/login?error=oauth_failed`);
    }
  }

  /**
   * Đăng xuất
   */
  async logout(req, res) {
    try {
      const token = req.headers.authorization?.split(' ')[1];
      
      if (token) {
        // Thêm token vào blacklist (nếu dùng Redis)
        // await redisClient.setex(`blacklist:${token}`, 3600, '1');
      }
      
      // Xóa cookie
      res.clearCookie('auth_token', {
        domain: process.env.NODE_ENV === 'production' ? '.edu.vnu' : undefined
      });
      
      logger.info(`User logged out`, { userId: req.user?.userId });
      
      res.json({
        success: true,
        message: 'Đăng xuất thành công'
      });
      
    } catch (error) {
      logger.error(`Logout error: ${error.message}`);
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi khi đăng xuất'
      });
    }
  }

  /**
   * Làm mới token
   */
  async refreshToken(req, res) {
    try {
      const { token } = req.body;
      
      if (!token) {
        return res.status(400).json({
          success: false,
          error: 'Token là bắt buộc'
        });
      }
      
      // Verify token (cho phép expired)
      const decoded = jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
      
      // Kiểm tra user còn tồn tại
      const userCheck = await db.query(
        'SELECT id, role, email FROM users WHERE id = $1 AND active = true',
        [decoded.userId]
      );
      
      if (userCheck.rows.length === 0) {
        return res.status(401).json({
          success: false,
          error: 'Tài khoản không tồn tại hoặc đã bị vô hiệu hóa'
        });
      }
      
      const user = userCheck.rows[0];
      
      // Tạo token mới
      const newToken = jwt.sign(
        { 
          userId: user.id, 
          role: user.role,
          email: user.email 
        },
        process.env.JWT_SECRET,
        { 
          expiresIn: process.env.JWT_EXPIRE,
          issuer: 'quanlygiaoduc.edu.vnu'
        }
      );
      
      res.json({
        success: true,
        data: { token: newToken }
      });
      
    } catch (error) {
      if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
          success: false,
          error: 'Token không hợp lệ'
        });
      }
      
      logger.error(`Refresh token error: ${error.message}`);
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi khi làm mới token'
      });
    }
  }

  /**
   * Quên mật khẩu
   */
  async forgotPassword(req, res) {
    try {
      const { email } = req.body;
      
      // Validate email
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
          success: false,
          error: 'Email không hợp lệ'
        });
      }
      
      // Tìm user (không thông báo nếu không tìm thấy để tránh enumeration)
      const result = await db.query(
        'SELECT id, full_name FROM users WHERE email = $1 AND active = true',
        [email]
      );
      
      if (result.rows.length > 0) {
        const user = result.rows[0];
        
        // Tạo reset token
        const resetToken = jwt.sign(
          { 
            userId: user.id, 
            type: 'password_reset',
            email: email 
          },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );
        
        // Lưu vào database
        await db.query(
          `UPDATE users 
           SET reset_token = $1, 
               reset_token_expires = NOW() + INTERVAL '1 hour',
               updated_at = NOW()
           WHERE id = $2`,
          [resetToken, user.id]
        );
        
        // Gửi email
        try {
          await emailService.sendPasswordResetEmail(email, user.full_name, resetToken);
        } catch (emailError) {
          logger.error(`Failed to send reset email: ${emailError.message}`, { userId: user.id });
        }
        
        logger.info(`Password reset requested: ${email}`, { userId: user.id });
      }
      
      // Luôn trả về cùng một response
      res.json({
        success: true,
        message: 'Nếu email tồn tại trong hệ thống, chúng tôi đã gửi hướng dẫn đặt lại mật khẩu.'
      });
      
    } catch (error) {
      logger.error(`Forgot password error: ${error.message}`, {
        email: req.body.email
      });
      
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi. Vui lòng thử lại sau.'
      });
    }
  }

  /**
   * Đặt lại mật khẩu
   */
  async resetPassword(req, res) {
    const transaction = await db.connect();
    
    try {
      const { token, newPassword } = req.body;
      
      if (!token || !newPassword) {
        return res.status(400).json({
          success: false,
          error: 'Token và mật khẩu mới là bắt buộc'
        });
      }
      
      if (newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          error: 'Mật khẩu phải có ít nhất 8 ký tự'
        });
      }
      
      await transaction.query('BEGIN');
      
      // Tìm user với token hợp lệ
      const result = await transaction.query(
        `SELECT id, email, reset_token_expires 
         FROM users 
         WHERE reset_token = $1 
           AND reset_token_expires > NOW()
         FOR UPDATE`,
        [token]
      );
      
      if (result.rows.length === 0) {
        await transaction.query('ROLLBACK');
        return res.status(400).json({
          success: false,
          error: 'Token không hợp lệ hoặc đã hết hạn. Vui lòng yêu cầu link mới.'
        });
      }
      
      const user = result.rows[0];
      
      // Hash password mới
      const hashedPassword = await bcrypt.hash(newPassword, 12);
      
      // Cập nhật password và xóa reset token
      await transaction.query(
        `UPDATE users 
         SET password = $1, 
             reset_token = NULL, 
             reset_token_expires = NULL,
             login_attempts = 0,
             locked_until = NULL,
             updated_at = NOW()
         WHERE id = $2`,
        [hashedPassword, user.id]
      );
      
      // Gửi email thông báo
      try {
        await emailService.sendPasswordChangedEmail(user.email);
      } catch (emailError) {
        logger.error(`Failed to send password changed email: ${emailError.message}`, { userId: user.id });
      }
      
      await transaction.query('COMMIT');
      
      logger.info(`Password reset successful for user: ${user.email}`, { userId: user.id });
      
      res.json({
        success: true,
        message: 'Mật khẩu đã được đặt lại thành công. Bạn có thể đăng nhập với mật khẩu mới.'
      });
      
    } catch (error) {
      await transaction.query('ROLLBACK');
      
      logger.error(`Reset password error: ${error.message}`, {
        token: req.body.token ? 'provided' : 'missing'
      });
      
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi. Vui lòng thử lại sau.'
      });
    } finally {
      transaction.release();
    }
  }

  /**
   * Xác thực token
   */
  async verifyToken(req, res) {
    try {
      // Middleware đã verify token
      res.json({
        success: true,
        data: {
          valid: true,
          user: req.user
        }
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        error: 'Token không hợp lệ'
      });
    }
  }

  /**
   * Lấy thông tin profile
   */
  async getProfile(req, res) {
    try {
      const userId = req.user.userId;
      
      const result = await db.query(
        `SELECT id, full_name, email, role, email_verified, 
                phone, avatar_url, created_at, updated_at, last_login
         FROM users WHERE id = $1`,
        [userId]
      );
      
      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'Người dùng không tồn tại'
        });
      }
      
      res.json({
        success: true,
        data: {
          user: result.rows[0]
        }
      });
      
    } catch (error) {
      logger.error(`Get profile error: ${error.message}`, { userId: req.user.userId });
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi khi lấy thông tin'
      });
    }
  }

  /**
   * Cập nhật profile
   */
  async updateProfile(req, res) {
    const transaction = await db.connect();
    
    try {
      const userId = req.user.userId;
      const { fullName, phone, avatarUrl } = req.body;
      
      await transaction.query('BEGIN');
      
      const updates = [];
      const values = [];
      let paramCount = 1;
      
      if (fullName) {
        updates.push(`full_name = $${paramCount}`);
        values.push(fullName);
        paramCount++;
      }
      
      if (phone !== undefined) {
        updates.push(`phone = $${paramCount}`);
        values.push(phone);
        paramCount++;
      }
      
      if (avatarUrl) {
        updates.push(`avatar_url = $${paramCount}`);
        values.push(avatarUrl);
        paramCount++;
      }
      
      if (updates.length === 0) {
        await transaction.query('ROLLBACK');
        return res.status(400).json({
          success: false,
          error: 'Không có thông tin nào để cập nhật'
        });
      }
      
      updates.push(`updated_at = NOW()`);
      values.push(userId);
      
      const query = `
        UPDATE users 
        SET ${updates.join(', ')}
        WHERE id = $${paramCount}
        RETURNING id, full_name, email, role, phone, avatar_url, updated_at
      `;
      
      const result = await transaction.query(query, values);
      
      await transaction.query('COMMIT');
      
      logger.info(`Profile updated for user: ${userId}`);
      
      res.json({
        success: true,
        message: 'Cập nhật thông tin thành công',
        data: {
          user: result.rows[0]
        }
      });
      
    } catch (error) {
      await transaction.query('ROLLBACK');
      
      logger.error(`Update profile error: ${error.message}`, { userId: req.user.userId });
      res.status(500).json({
        success: false,
        error: 'Đã xảy ra lỗi khi cập nhật thông tin'
      });
    } finally {
      transaction.release();
    }
  }

  /**
   * Xác thực email
   */
  async verifyEmail(req, res) {
    const transaction = await db.connect();
    
    try {
      const { token } = req.params;
      
      if (!token) {
        return res.redirect(`${process.env.FRONTEND_URL}/verification?error=invalid_token`);
      }
      
      await transaction.query('BEGIN');
      
      // Tìm user với verification token
      const result = await transaction.query(
        `SELECT id, email, verification_token 
         FROM users 
         WHERE verification_token = $1 
         FOR UPDATE`,
        [token]
      );
      
      if (result.rows.length === 0) {
        await transaction.query('ROLLBACK');
        return res.redirect(`${process.env.FRONTEND_URL}/verification?error=invalid_token`);
      }
      
      const user = result.rows[0];
      
      // Verify token
      try {
        jwt.verify(token, process.env.JWT_SECRET);
      } catch (error) {
        await transaction.query('ROLLBACK');
        
        if (error.name === 'TokenExpiredError') {
          // Gửi email verification mới
          const newToken = jwt.sign(
            { userId: user.id, type: 'email_verification' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
          );
          
          await db.query(
            'UPDATE users SET verification_token = $1 WHERE id = $2',
            [newToken, user.id]
          );
          
          await emailService.sendVerificationEmail(user.email, user.full_name, newToken);
          
          return res.redirect(`${process.env.FRONTEND_URL}/verification?error=token_expired&resent=true`);
        }
        
        return res.redirect(`${process.env.FRONTEND_URL}/verification?error=invalid_token`);
      }
      
      // Cập nhật email đã xác thực
      await transaction.query(
        `UPDATE users 
         SET email_verified = true, 
             verification_token = NULL,
             updated_at = NOW()
         WHERE id = $1`,
        [user.id]
      );
      
      await transaction.query('COMMIT');
      
      logger.info(`Email verified: ${user.email}`, { userId: user.id });
      
      res.redirect(`${process.env.FRONTEND_URL}/verification?success=true`);
      
    } catch (error) {
      await transaction.query('ROLLBACK');
      
      logger.error(`Email verification error: ${error.message}`, {
        token: req.params.token
      });
      
      res.redirect(`${process.env.FRONTEND_URL}/verification?error=server_error`);
    } finally {
      transaction.release();
    }
  }
}

module.exports = new AuthController();
