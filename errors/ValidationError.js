import { AppError } from "./AppError.js";

export default class ValidationError extends AppError {
    constructor(message = "Validation failed", errors = []) {
        super(message, 400, true);
        this.name = "ValidationError";
        this.errors = errors;
    }
}

export { ValidationError };
