const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { body, validationResult } = require("express-validator");
const nodemailer = require("nodemailer");
const Token = require("../models/Token");
const auth = require("../middleware/auth")

router.post("/register", async (req, res) => {
    const { name, email, phoneNo, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) return res.status(400).json({ msg: "User already exists" });
        let phone = await User.findOne({ phoneNo });
        if (phone)
            return res.status(400).json({ msg: "Phone Number already exists" });

        user = new User({ name, email, phoneNo, password });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();

        const payload = { user: { id: user.id } };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: "1h" },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: "Invalid credentials" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(400).json({ msg: "Invalid credentials" });

        const payload = { user: { id: user.id } };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: "1h" },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

router.post(
    "/forgot-password",
    body("email")
        .isEmail()
        .withMessage("Please provide a valid email address."),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email } = req.body;

        try {
            let user = await User.findOne({ email });
            if (!user) {
                return res.status(400).json({ msg: "User not found" });
            }

            let token = await Token.findOne({ userId: user._id });
            if (token) await token.deleteOne();

            const resetToken = crypto.randomBytes(32).toString("hex");
            const hashedToken = crypto
                .createHash("sha256")
                .update(resetToken)
                .digest("hex");

            const newToken = new Token({
                userId: user._id,
                token: hashedToken,
            });
            await newToken.save();

            const resetLink = `${req.protocol}://${process.env.FRONTEND_URL}/password-reset/${resetToken}`;

            const transporter = nodemailer.createTransport({
                service: "Gmail",
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS,
                },
            });

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: "Password Reset Link",
                text: `Click the link to reset your password: ${resetLink}`,
            };

            await transporter.sendMail(mailOptions);
            res.json({ msg: "Password reset link sent to your email" });
        } catch (err) {
            console.error(err.message);
            if (err instanceof nodemailer.SendMailError) {
                return res.status(500).json({
                    msg: "Failed to send email. Please try again later.",
                });
            }
            res.status(500).send("Server error");
        }
    }
);

router.post("/password-reset/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const hashedToken = crypto
            .createHash("sha256")
            .update(token)
            .digest("hex");
        const resetToken = await Token.findOne({ token: hashedToken });

        if (!resetToken)
            return res.status(400).json({ msg: "Invalid or expired token" });

        let user = await User.findById(resetToken.userId);
        if (!user) return res.status(400).json({ msg: "User not found" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        await user.save();

        await resetToken.deleteOne();
        res.json({ msg: "Password updated successfully" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// GET: Get user profile
router.get("/profile", auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");
        if (!user) return res.status(404).json({ msg: "User not found" });

        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// PUT: Update user profile
router.put("/profile", auth, async (req, res) => {
    const { name, email } = req.body;
    try {
        // Find the user by ID (authenticated user)
        let user = await User.findById(req.user.id);

        if (!user) return res.status(404).json({ msg: "User not found" });

        // Update user fields
        user.name = name || user.name;
        user.email = email || user.email;

        await user.save();
        res.json({ msg: "Profile updated successfully", user });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// PUT: Change user password
router.put('/change-password', auth, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
  
    try {
      // Find the user by ID
      const user = await User.findById(req.user.id);
  
      if (!user) return res.status(404).json({ msg: 'User not found' });
  
      // Check if the old password is correct
      const isMatch = await bcrypt.compare(oldPassword, user.password);
      if (!isMatch) return res.status(400).json({ msg: 'Incorrect old password' });
  
      // Hash the new password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
  
      await user.save();
      res.json({ msg: 'Password updated successfully' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  });

module.exports = router;
