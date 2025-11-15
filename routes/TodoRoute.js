import express from 'express';
import * as todoController from "../controllers/TodoController.js";
import { authenticateJWT, isAdmin, isOwnerOrAdmin } from '../middleware/auth.js';
import asyncWrapper from '../middleware/asyncWrapper.js';
import { getAllTasksValidationSchema } from '../validators/toDos/getAllValidator.js';
import { createTaskValidationSchema } from '../validators/toDos/createValidator.js';
import { updateTaskValidationSchema } from '../validators/toDos/updateValidator.js';
import { taskIdValidationSchema } from '../validators/toDos/getByIdValidator.js';
import { handleValidationErrors } from '../validators/handleValidationError.js';

const todoRouter = express.Router();

todoRouter.get('/', authenticateJWT, getAllTasksValidationSchema, handleValidationErrors, asyncWrapper(todoController.getAll));
todoRouter.post('/', authenticateJWT, createTaskValidationSchema, handleValidationErrors, asyncWrapper(todoController.create));
todoRouter.get('/:id', authenticateJWT, isOwnerOrAdmin, taskIdValidationSchema, handleValidationErrors, asyncWrapper(todoController.getById));
todoRouter.put('/:id', authenticateJWT, isAdmin, updateTaskValidationSchema, handleValidationErrors, asyncWrapper(todoController.update));
todoRouter.delete('/:id', authenticateJWT, isAdmin, taskIdValidationSchema, handleValidationErrors, asyncWrapper(todoController.remove));
todoRouter.patch('/:id/toggle', authenticateJWT, isAdmin, asyncWrapper(todoController.toggleCompleted));

export default todoRouter;