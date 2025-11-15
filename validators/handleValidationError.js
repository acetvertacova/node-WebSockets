import { ValidationError } from "../errors/ValidationError.js";
import { validationResult } from "express-validator";

const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const errorDetails = errors.array().map((err) => ({
            field: err.param,
            message: err.msg,
        }));
        return next(new ValidationError("Validation failed", errorDetails));
    }
    next();
};

export { handleValidationErrors };