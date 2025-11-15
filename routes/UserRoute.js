import express from 'express';
import * as userController from "../controllers/UserController.js";
import { authenticateJWT } from '../middleware/auth.js';
import asyncWrapper from '../middleware/asyncWrapper.js';
import { registrationValidationSchema } from '../validators/users/registrationValidator.js';
import { loginValidationSchema } from '../validators/users/loginValidator.js';
import { handleValidationErrors } from '../validators/handleValidationError.js';

const userRouter = express.Router();

userRouter.post('/register', registrationValidationSchema, handleValidationErrors, asyncWrapper(userController.register));
userRouter.post('/login', loginValidationSchema, handleValidationErrors, asyncWrapper(userController.login));
userRouter.get('/profile', authenticateJWT, asyncWrapper(userController.getProfile));

export default userRouter;