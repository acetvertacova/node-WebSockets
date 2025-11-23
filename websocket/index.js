import { WebSocketServer } from "ws";
import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.JWT_SECRET || 3000;
let wss = null;

export function initWebSocket(server) {
    wss = new WebSocketServer({ server });

    wss.on("connection", (ws, req) => {
        console.log("WS: client connecting...");

        const params = new URLSearchParams(req.url.replace("/?", ""));
        const token = params.get("token");

        if (!token) {
            ws.close(4001, "Auth required");
            return;
        }

        try {
            const payload = jwt.verify(token, SECRET_KEY);
            ws.user = payload;
            console.log(`WS: connected user ${ws.user.id}`);
        } catch (err) {
            ws.close(4002, "Invalid token");
            return;
        }

        ws.on("message", m => console.log(`WS message: ${m}`));
        ws.on("close", () => console.log("WS: client disconnected"));

        ws.send("Welcome to WebSocket server!");
    });

    return wss;
}

export function getWss() {
    return wss;
}
