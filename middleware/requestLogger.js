import logger from "../utils/logger.js";
import { v4 as uuidv4 } from "uuid";

const requestLogger = (req, res, next) => {
    const requestId = uuidv4();
    req.requestId = requestId;
    const start = Date.now();

    logger.info("Incoming request", {
        requestId,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get("user-agent"),
    });

    res.on("finish", () => {
        const responseTime = Date.now() - start;
        const logData = {
            requestId,
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            responseTime,
        };

        if (res.statusCode >= 400) {
            logger.error("Request failed", logData);
        } else {
            logger.info("Request completed", logData);
        }
    });

    next();
};

export default requestLogger;
