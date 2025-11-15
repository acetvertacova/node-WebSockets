import logger from "../utils/logger.js";

const errorHandler = (err, req, res, next) => {
    const isDev = process.env.NODE_ENV === "development";
    const statusCode = err.statusCode || 500;
    const logData = {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        statusCode,
        message: err.message,
    };

    logger.error("Error:", logData);
    const response = {
        status: "error",
        message: err.message || "Unexpected error occurred",
    };

    if (Array.isArray(err.errors) && err.errors.length > 0) {
        response.errors = err.errors;
    }

    res.status(err.isOperational ? statusCode : 500).json(response);
};

export default errorHandler;