import { getWss } from "./index.js";

export function notifyUser(userId, message) {
    const wss = getWss();

    wss.clients.forEach(client => {
        if (client.user?.id === userId && client.readyState === 1) {
            client.send(JSON.stringify(message));
        }
    });
}