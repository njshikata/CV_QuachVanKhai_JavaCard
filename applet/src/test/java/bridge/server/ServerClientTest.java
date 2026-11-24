package bridge.server;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerClientTest {

    @Test
    void extractsServerMessage() {
        assertEquals("Sai mã xác nhận (còn 4 lần)",
                ServerClient.errorMessage(400, "{\"message\":\"Sai mã xác nhận (còn 4 lần)\"}"));
    }

    @Test
    void fallbackWhenNotJson() {
        assertTrue(ServerClient.errorMessage(500, "<html>boom</html>").contains("500"));
        assertTrue(ServerClient.errorMessage(401, "").contains("HMAC"));
        assertTrue(ServerClient.errorMessage(404, "{}").contains("404"));
    }
}
