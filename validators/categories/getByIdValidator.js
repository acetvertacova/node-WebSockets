import { param } from "express-validator";

export const categoryIdValidationSchema = [
    param("id")
        .isInt()
        .withMessage("Category ID must be a valid UUID")
];