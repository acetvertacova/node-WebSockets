import jwt from 'jsonwebtoken';
import db from '../models/index.js';
import { AuthenticationError } from '../errors/AuthenticationError.js';
import { ToDoNotFoundError } from '../errors/404/ToDoNotFoundError.js';
const Todo = db.Todo;

const SECRET_KEY = process.env.JWT_SECRET || 'your_secret_key';

export function authenticateJWT(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        return next(new AuthenticationError("Token missing"));
    }

    const token = authHeader.split(" ")[1];

    try {
        const payload = jwt.verify(token, SECRET_KEY);
        req.user = payload;
        next();
    } catch (err) {
        console.log(err);
        return next(new AuthenticationError("Invalid token"));
    }
}

export function isAdmin(req, res, next) {
    if (!req.user) {
        return next(new AuthenticationError("Unathorized"));
    }

    if (req.user.role !== 'admin') {
        return next(new AuthenticationError("Admins only"), 403);
    }

    next();
}

export async function isOwnerOrAdmin(req, res, next) {
    const user = req.user;
    const todoId = req.params.id;

    if (!user) {
        return next(new AuthenticationError("Unauthorized"));
    }

    try {
        const todo = await Todo.findByPk(todoId);

        if (!todo) {
            return next(new ToDoNotFoundError("Task not found", 404));
        }

        if (user.role === 'admin' || todo.user_id === user.id) {
            return next();
        }

        return next(new AuthenticationError("Forbidden: Not owner or admin", 403));
    } catch (err) {
        return res.status(500).json({ message: 'Server error' });
    }
}