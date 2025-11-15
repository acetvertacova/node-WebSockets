import { NotFoundError } from "../NotFoundError.js";

class CategoryNotFoundError extends NotFoundError {
    constructor(categoryId) {
        super(`Category with ID ${categoryId}`);
    }
}

export { CategoryNotFoundError };