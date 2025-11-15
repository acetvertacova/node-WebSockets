import { body } from "express-validator";

export const registrationValidationSchema = [
    body("username")
        .trim()
        .notEmpty()
        .withMessage("Username is required")
        .isLength({ min: 2 })
        .withMessage("Username must be at least 2 characters"),

    body("email")
        .trim()
        .isEmail()
        .withMessage("Invalid email format")
        .normalizeEmail(),

    body("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters")
        .matches(/[A-Z]/)
        .withMessage("Password must contain an uppercase letter")
        .matches(/[0-9]/)
        .withMessage("Password must contain a number"),
];