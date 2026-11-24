package main;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CardBridgeServer {

    public static final int PORT = 8088;

    public static void main(String[] args) throws IOException {
        start(new CardService());
    }

    public static void start(CardService svc) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        // Đầu đọc
        server.createContext("/bridge/status",          ex -> handle(ex, body -> svc.status()));
        server.createContext("/bridge/card/public-key", ex -> handle(ex, body -> svc.publicKey()));
        server.createContext("/bridge/reader/new-card", ex -> handle(ex, body -> svc.createAndInsertNewCard()));
        server.createContext("/bridge/reader/insert",   ex -> handle(ex, body -> svc.insertSlot(getStr(body, "slot"))));
        server.createContext("/bridge/reader/reset",    ex -> handle(ex, body -> svc.resetReader()));

        // Thẻ & PIN
        server.createContext("/bridge/card/pin/verify", ex -> handle(ex, body ->
                svc.verifyPin(getStr(body, "expectedCardUid"), getStr(body, "pin"))));
        server.createContext("/bridge/card/pin/change", ex -> handle(ex, body ->
                svc.changePin(getStr(body, "expectedCardUid"), getStr(body, "oldPin"), getStr(body, "newPin"))));
        server.createContext("/bridge/card/pin/admin",  ex -> handle(ex, body ->
                svc.adminPin(getStr(body, "expectedCardUid"), getStr(body, "action"), getStr(body, "adminPayloadHex"))));

        // Dữ liệu AES & Ký RSA
        server.createContext("/bridge/card/info",  ex -> handle(ex, body ->
                svc.writeInfo(getStr(body, "expectedCardUid"), getStr(body, "adminPayloadHex"), getStr(body, "infoText"))));
        server.createContext("/bridge/card/image", ex -> handle(ex, body ->
                svc.writeImage(getStr(body, "expectedCardUid"), getStr(body, "adminPayloadHex"), getStr(body, "imageHex"))));
        server.createContext("/bridge/card/read",  ex -> handle(ex, body ->
                svc.readAll(getStr(body, "expectedCardUid"), getStr(body, "pin"), getBool(body, "includeImage"))));
        server.createContext("/bridge/card/sign",  ex -> handle(ex, body ->
                svc.signChallenge(getStr(body, "expectedCardUid"), getStr(body, "challengeHex"))));

        // Ví điện tử MAC
        server.createContext("/bridge/card/credit",  ex -> handle(ex, body ->
                svc.credit(getStr(body, "expectedCardUid"), getStr(body, "payloadHex"))));
        server.createContext("/bridge/card/debit",   ex -> handle(ex, body ->
                svc.debit(getStr(body, "expectedCardUid"), getStr(body, "pin"), getStr(body, "payloadHex"))));
        server.createContext("/bridge/card/balance", ex -> handle(ex, body ->
                svc.balance(getStr(body, "expectedCardUid"), getStr(body, "pin"))));

        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        System.out.println("🚀 Virtual Smart Card Bridge (/bridge/**) dang chay tai http://localhost:" + PORT);
    }

    @FunctionalInterface
    interface BridgeAction {
        CardService.BridgeResult run(String body) throws Exception;
    }

    private static void handle(HttpExchange ex, BridgeAction action) throws IOException {
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=UTF-8");
        byte[] rawBody = readBytes(ex.getRequestBody());

        String tsHeader = ex.getRequestHeaders().getFirst("X-Gateway-Timestamp");
        String sigHeader = ex.getRequestHeaders().getFirst("X-Gateway-Signature");
        if (!verifyHmac(tsHeader, sigHeader, ex.getRequestMethod(), ex.getRequestURI().getPath(), rawBody)) {
            send(ex, 401, "{\"message\":\"Sai chữ ký HMAC gateway\"}");
            return;
        }

        CardService.BridgeResult res;
        try {
            String bodyStr = new String(rawBody, StandardCharsets.UTF_8);
            res = action.run(bodyStr);
        } catch (Exception e) {
            res = new CardService.BridgeResult(500, "{\"message\":\"" + e.getMessage() + "\"}");
        }
        send(ex, res.httpStatus, res.jsonBody);
    }

    private static boolean verifyHmac(String tsHeader, String sigHeader, String method, String path, byte[] body) {
        if (tsHeader == null || sigHeader == null) return false;
        try {
            long ts = Long.parseLong(tsHeader);
            if (Math.abs(System.currentTimeMillis() - ts) > 60_000L) return false;
            String expected = CardService.signGateway(ts, method, path, body);
            return MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.UTF_8),
                    sigHeader.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    private static void send(HttpExchange ex, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static byte[] readBytes(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int len;
        while ((len = is.read(buf)) != -1) baos.write(buf, 0, len);
        return baos.toByteArray();
    }

    private static String getStr(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\"").matcher(json);
        return m.find() ? m.group(1).replace("\\\"", "\"").replace("\\\\", "\\") : "";
    }

    private static boolean getBool(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(true|false)").matcher(json);
        return m.find() && Boolean.parseBoolean(m.group(1));
    }
}