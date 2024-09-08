import { Request, Response, NextFunction } from 'express';
import User from '../model/user.model'; // Adjust the import path based on your project structure
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'; // Uncomment if JWT functionality is required

export const SignUp = async (req: Request, res: Response, next: NextFunction) => {
    const { name, email, password, role } = req.body;

    // Validate input
    if (!name || !email || !password || !role) {
        return res.status(400).json({ message: "Name, email, password, and role are required" });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists", data: existingUser });
        }

        // Create a new user
        const user = new User({
            name,
            email,
            passwordHash: password, // Password is handled by the schema's `set` method
            role
        });

        await user.save();

        // Generate JWT token if needed
        // const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY!, { expiresIn: '7d' });

        return res.status(201).json({ message: "User created successfully", user });
    } catch (err) {
        console.error(err); // Log the error for debugging
        return res.status(500).json({ message: "Error creating user" });
    }
};

export const SignIn = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }

        // Find the user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: "Unauthorized user" });
        }

        // Check if the password is valid
        const isPasswordValid = User.checkPassword(password, user.passwordHash);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // Generate a JWT token if needed
        // const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY!, { expiresIn: '7d' });

        return res.status(200).json({ message: "User signed in successfully", user });
    } catch (err) {
        console.error(err); // Log the error for debugging
        return res.status(500).json({ error: "Internal server error" });
    }
};

import { Request, Response, NextFunction } from 'express';
import User from '../models/user.model'; // Adjust the import path based on your project structure
import bcrypt from 'bcryptjs'; // Ensure bcrypt is imported

export const updatePassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, password, newPassword } = req.body;

        // Validate input
        if (!email || !password || !newPassword) {
            return res.status(400).json({ message: "Email, current password, and new password are required" });
        }

        // Find the user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        // Check if the current password is correct
        const isPasswordCorrect = User.checkPassword(password, user.passwordHash);

        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Current password is incorrect" });
        }

        // Update the password
        user.passwordHash = bcrypt.hashSync(newPassword, 10);
        await user.save();

        return res.status(200).json({ message: "Password updated successfully" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal server error" });
    }
};

export const generateToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { email, password } = req.body;

        // Validate input
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password are required" });
        }

        // Find the user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: "Unauthorized user" });
        }

        // Verify the password
        const isPasswordValid = User.checkPassword(password, user.passwordHash);

        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // Create JWT token
        const payload = { userId: user.userId, email: user.email, role: user.role };
        const token = jwt.sign(payload, process.env.SECRET_KEY!, { expiresIn: '7d' });

        console.log(`${email} ${token}`); // Optional: for debugging

        return res.status(200).json({ message: "Token created successfully", token });
    } catch (err) {
        console.error(err); // Log the error for debugging
        return res.status(500).json({ error: "Internal server error" });
    }
};
