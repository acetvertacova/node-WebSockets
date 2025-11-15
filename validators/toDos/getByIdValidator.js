import { param } from "express-validator";

export const taskIdValidationSchema = [
    param("id")
        .isUUID()
        .withMessage("Task ID must be a valid UUID")
];