import { body } from "express-validator";

export const createCategoryValidationSchema = [
    body("name")
        .trim()
        .notEmpty()
        .withMessage("Name is required")
        .isLength({ min: 2 })
        .withMessage("Name must be at least 2 characters long")
];
