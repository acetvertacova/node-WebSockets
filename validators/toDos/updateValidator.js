import { body } from "express-validator";

export const updateTaskValidationSchema = [
    body("title")
        .optional()
        .trim()
        .isLength({ min: 3 })
        .withMessage("Title must be at least 3 characters long"),

    body("completed")
        .optional()
        .isBoolean()
        .withMessage("Completed must be true or false"),

    body("category_id")
        .optional()
        .isInt({ gt: 0 })
        .withMessage("Category ID must be a positive integer")
];