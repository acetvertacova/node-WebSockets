import db from '../models/index.js';
import { UserNotFoundError } from "../errors/404/UserNotFoundError.js";
import { AuthenticationError } from "../errors/AuthenticationError.js";
import { ValidationError } from "../errors/ValidationError.js";
import { Op } from 'sequelize';
import logger from '../utils/logger.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
const User = db.User;
const SECRET_KEY = process.env.JWT_SECRET || 'your_secret_key';

export async function register(req, res) {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const existingUser = await User.findOne({
        where: {
            [Op.or]: [{ email }, { username }]
        }
    });

    if (existingUser) {
        throw new ValidationError("Validation failed", [
            { field: "email", message: "Email already registered" },
            { field: "username", message: "Username already taken" }
        ]);
    }

    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    logger.info("New user registered", {
        username, email, requestId: req.requestId
    });

    res.status(201).json({ message: 'User registered successfully' });
};

export async function login(req, res) {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });

    if (!user) {
        throw new AuthenticationError("Credintials are wrong");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        throw new AuthenticationError("Credintials are wrong");
    }

    const payload = { id: user.id, username: user.username, role: user.role };

    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "15m" });
    res.json({ token: token });
}

export async function getProfile(req, res) {
    const user = await User.findByPk(req.user.id, {
        attributes: { exclude: ['password'] }
    });

    if (!user) throw new UserNotFoundError(req.user.id);
    res.json(user);
}