import { NotFoundError } from "../NotFoundError.js";

class UserNotFoundError extends NotFoundError {
    constructor(userId) {
        super(`User with ID ${userId} not found`);
    }
}

export { UserNotFoundError };