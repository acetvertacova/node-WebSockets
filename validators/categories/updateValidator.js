import { body } from "express-validator";

export const updateCategoryValidationSchema = [
    body("name")
        .optional()
        .trim()
        .isLength({ min: 2 })
        .withMessage("Name must be at least 2 characters long")
];