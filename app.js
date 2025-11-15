import express from "express";
import dotenv from "dotenv";
import categoryRouter from "./routes/CategoryRoute.js";
import todoRouter from "./routes/TodoRoute.js";
import { swaggerUi, specs } from "./swagger/swagger.js";
import userRouter from "./routes/UserRoute.js";
import errorHandler from "./middleware/errorHandler.js";
import requestLogger from "./middleware/requestLogger.js";

const app = express();
app.use(requestLogger);
dotenv.config();

const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/categories', categoryRouter);
app.use('/api/todos', todoRouter);
app.use('/api/auth', userRouter);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

app.use((req, res, next) => {
    const error = new AppError("Route not found", 404);
    next(error);
});

app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});