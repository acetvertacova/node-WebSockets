import { AppError } from "./AppError.js";

class AuthenticationError extends AppError {
    constructor(message = "Authentication failed", statusCode = 401) {
        super(message, statusCode);
        this.name = "AuthenticationError";
    }
}

export { AuthenticationError };
