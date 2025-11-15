import { body } from "express-validator";

export const createTaskValidationSchema = [
    body("title")
        .trim()
        .notEmpty()
        .withMessage("Title is required")
        .isLength({ min: 3 })
        .withMessage("Title must be at least 3 characters long"),

    body("category_id")
        .optional()
        .isInt({ gt: 0 })
        .withMessage("Category ID must be a positive integer")
];