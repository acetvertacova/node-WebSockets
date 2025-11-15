import express from 'express';
import * as categoryController from "../controllers/CategoriesController.js";
import { authenticateJWT, isAdmin } from '../middleware/auth.js';
import asyncWrapper from '../middleware/asyncWrapper.js';
import { createCategoryValidationSchema } from '../validators/categories/createValidator.js';
import { updateCategoryValidationSchema } from '../validators/categories/updateValidator.js';
import { categoryIdValidationSchema } from '../validators/categories/getByIdValidator.js';
import { handleValidationErrors } from '../validators/handleValidationError.js';

const categoryRouter = express.Router();

categoryRouter.get('/', authenticateJWT, isAdmin, asyncWrapper(categoryController.getAll));
categoryRouter.post('/', authenticateJWT, isAdmin, createCategoryValidationSchema, handleValidationErrors, asyncWrapper(categoryController.create));
categoryRouter.get('/:id', authenticateJWT, isAdmin, categoryIdValidationSchema, handleValidationErrors, asyncWrapper(categoryController.getById));
categoryRouter.put('/:id', authenticateJWT, isAdmin, updateCategoryValidationSchema, handleValidationErrors, asyncWrapper(categoryController.update));
categoryRouter.delete('/:id', authenticateJWT, isAdmin, categoryIdValidationSchema, handleValidationErrors, asyncWrapper(categoryController.remove));

export default categoryRouter;
