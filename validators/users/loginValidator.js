import { body } from "express-validator";

export const loginValidationSchema = [
    body("username")
        .trim()
        .notEmpty()
        .withMessage("Username is required"),

    body("password")
        .notEmpty()
        .withMessage("Password is required")
];
