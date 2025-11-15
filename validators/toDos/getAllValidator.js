import { query } from "express-validator";

export const getAllTasksValidationSchema = [
    query("page")
        .optional()
        .isInt({ gt: 0 })
        .withMessage("Page must be a positive number"),
    query("limit")
        .optional()
        .isInt({ gt: 0 })
        .withMessage("Limit must be a positive number"),
    query("category")
        .optional()
        .isUUID()
        .withMessage("Category ID must be a valid UUID"),
    query("sort")
        .optional()
        .matches(/^(createdAt|updatedAt|dueDate):(asc|desc)$/i)
        .withMessage("Sort must be in format field:direction, e.g. createdAt:desc")
];
