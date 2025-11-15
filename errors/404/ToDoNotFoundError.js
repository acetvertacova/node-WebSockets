import { NotFoundError } from "../NotFoundError.js";

class ToDoNotFoundError extends NotFoundError {
    constructor(todoId) {
        super(`Task with ID ${todoId} not found`);
    }
}

export { ToDoNotFoundError };