import http from "http";
import app from "./app.js";
import { initWebSocket } from "./websocket/index.js";

const server = http.createServer(app);

initWebSocket(server);

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
