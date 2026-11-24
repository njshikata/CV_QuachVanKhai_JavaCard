package main;

import applet.Config;
import applet.MainApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

public class CardService {
    public static final byte CLA = 0x00;
    private static final int IMG_CHUNK_SIZE = 192;

    // PHẢI KHỚP 100% với app.card.gateway-secret trong application.properties của Spring Boot
    public static final String GATEWAY_SECRET = System.getProperty(
            "card.gateway.secret", "c9a7f3e18b42d6059e1c4a7b2f8d3065a1e9c7b4d2f803619a5e3c7b1f4d8206");
    public static final String SPRING_BOOT_URL = System.getProperty(
            "springboot.url", "http://localhost:8080");

    public static class BridgeResult {
        public final int httpStatus;
        public final String jsonBody;

        public BridgeResult(int httpStatus, String jsonBody) {
            this.httpStatus = httpStatus;
            this.jsonBody = jsonBody;
        }
    }

    private static class CardSlot {
        final String cardUid;
        final String modulusHex;
        final String exponentHex;
        final CardSimulator simulator;
        final AID aid;

        CardSlot(String cardUid, String modulusHex, String exponentHex, CardSimulator simulator, AID aid) {
            this.cardUid = cardUid;
            this.modulusHex = modulusHex;
            this.exponentHex = exponentHex;
            this.simulator = simulator;
            this.aid = aid;
        }
    }

    private final Map<String, CardSlot> slots = new LinkedHashMap<>();
    private CardSlot activeSlot;
    private Consumer<String> statusListener = s -> {};

    public CardService() {
        createAndInsertNewCard();
    }

    public void setStatusListener(Consumer<String> listener) {
        if (listener != null) this.statusListener = listener;
    }

    public synchronized String getActiveCardUid() {
        return activeSlot == null ? "" : activeSlot.cardUid;
    }

    // =========================================================================
    // KHI BẤM "QUÉT THẺ" BÊN JAVA CARD -> RESET SESSION & BÁO SANG SPRING BOOT
    // =========================================================================
    public synchronized String tapCardToSpringBoot() throws Exception {
        if (activeSlot == null) createAndInsertNewCard();
        activeSlot.simulator.reset();
        activeSlot.simulator.selectApplet(activeSlot.aid);

        String path = "/api/card-gateway/tap";
        String bodyStr = "{\"cardUid\":\"" + activeSlot.cardUid + "\"}";
        byte[] bodyBytes = bodyStr.getBytes(StandardCharsets.UTF_8);
        long ts = System.currentTimeMillis();
        String sig = signGateway(ts, "POST", path, bodyBytes);

        URL url = new URL(SPRING_BOOT_URL + path);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(4000);
        conn.setReadTimeout(4000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("X-Gateway-Id", "JAVACARD-READER-01");
        conn.setRequestProperty("X-Gateway-Timestamp", String.valueOf(ts));
        conn.setRequestProperty("X-Gateway-Signature", sig);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }

        int code = conn.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
        String resp = readStream(is);
        if (code >= 400) {
            throw new IllegalStateException("Spring Boot từ chối (" + code + "): " + resp);
        }
        return activeSlot.cardUid;
    }

    // =========================================================================
    // CÁC API BRIDGE PHỤC VỤ SPRING BOOT (/bridge/**)
    // =========================================================================
    public synchronized BridgeResult status() {
        boolean present = (activeSlot != null);
        String uid = present ? activeSlot.cardUid : "";
        return new BridgeResult(200,
                "{\"mode\":\"SIM\",\"reader\":\"jCardSim\",\"cardPresent\":" + present +
                        ",\"cardUid\":\"" + uid + "\"}");
    }

    public synchronized BridgeResult publicKey() {
        if (activeSlot == null) return err(409, "Chưa có thẻ trong đầu đọc", "6985", null);
        return new BridgeResult(200,
                "{\"cardUid\":\"" + activeSlot.cardUid + "\"," +
                        "\"modulusHex\":\"" + activeSlot.modulusHex + "\"," +
                        "\"exponentHex\":\"" + activeSlot.exponentHex + "\"}");
    }

    public synchronized BridgeResult createAndInsertNewCard() {
        CardSimulator sim = new CardSimulator();
        AID aid = AIDUtil.create("F000000001");
        sim.installApplet(aid, MainApplet.class);
        sim.selectApplet(aid);

        ResponseAPDU resMod = sim.transmitCommand(new CommandAPDU(CLA, Config.INS_GET_PUB_MOD, 0, 0, 128));
        ResponseAPDU resExp = sim.transmitCommand(new CommandAPDU(CLA, Config.INS_GET_PUB_EXP, 0, 0, 16));
        String modHex = bytesToHex(resMod.getData());
        String expHex = bytesToHex(resExp.getData());
        String uid = fingerprint(resMod.getData(), resExp.getData());

        CardSlot slot = new CardSlot(uid, modHex, expHex, sim, aid);
        slots.put(uid, slot);
        activeSlot = slot;
        statusListener.accept("THẺ MỚI: " + uid);

        return new BridgeResult(200,
                "{\"cardUid\":\"" + uid + "\",\"slot\":\"" + uid + "\"," +
                        "\"modulusHex\":\"" + modHex + "\",\"exponentHex\":\"" + expHex + "\"}");
    }

    public synchronized BridgeResult insertSlot(String slotUid) {
        if (slotUid == null || slotUid.trim().isEmpty()) {
            return err(400, "Thiếu slot/cardUid", null, null);
        }
        String key = slotUid.trim().toUpperCase();
        CardSlot found = slots.get(key);
        if (found == null) {
            return err(409, "Không tìm thấy thẻ ảo slot " + key + " trong simulator", "6985", null);
        }
        found.simulator.reset();
        found.simulator.selectApplet(found.aid);
        activeSlot = found;
        statusListener.accept("ĐÃ NẠP THẺ: " + key);
        return new BridgeResult(200, "{\"ok\":true,\"cardUid\":\"" + key + "\"}");
    }

    public synchronized BridgeResult resetReader() {
        if (activeSlot != null) {
            activeSlot.simulator.reset();
            activeSlot.simulator.selectApplet(activeSlot.aid);
        }
        return new BridgeResult(200, "{\"ok\":true}");
    }

    public synchronized BridgeResult verifyPin(String expectedUid, String pin) {
        BridgeResult chk = checkExpectedUid(expectedUid);
        if (chk != null) return chk;

        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_VERIFY_PIN, 0, 0, pin.getBytes(StandardCharsets.UTF_8)));
        int tries = getTriesRemaining();
        if (res.getSW() != 0x9000) {
            return err(422, tries == 0 ? "Thẻ đã bị khóa PIN" : "Sai mã PIN", swHex(res.getSW()), tries);
        }
        statusListener.accept("XÁC THỰC PIN OK (" + activeSlot.cardUid + ")");
        return new BridgeResult(200, "{\"ok\":true,\"pinTriesRemaining\":" + tries + "}");
    }

    public synchronized BridgeResult changePin(String expectedUid, String oldPin, String newPin) {
        BridgeResult v = verifyPin(expectedUid, oldPin);
        if (v.httpStatus != 200) return v;

        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_CHANGE_PIN, 0, 0, newPin.getBytes(StandardCharsets.UTF_8)));
        if (res.getSW() != 0x9000) {
            return err(422, "Đổi PIN thất bại", swHex(res.getSW()), getTriesRemaining());
        }
        statusListener.accept("ĐỔI PIN THÀNH CÔNG");
        return new BridgeResult(200, "{\"ok\":true}");
    }

    public synchronized BridgeResult adminPin(String expectedUid, String action, String adminPayloadHex) {
        BridgeResult chk = checkExpectedUid(expectedUid);
        if (chk != null) return chk;

        byte ins = "RESET".equalsIgnoreCase(action) ? Config.INS_RESET_PIN : Config.INS_UNBLOCK_PIN;
        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, ins, 0, 0, hexToBytes(adminPayloadHex)));
        if (res.getSW() != 0x9000) {
            return err(422, "Lệnh Admin PIN bị từ chối", swHex(res.getSW()), getTriesRemaining());
        }
        return new BridgeResult(200, "{\"ok\":true,\"pinTriesRemaining\":" + getTriesRemaining() + "}");
    }

    public synchronized BridgeResult writeInfo(String expectedUid, String adminPayloadHex, String infoText) {
        BridgeResult chk = checkExpectedUid(expectedUid);
        if (chk != null) return chk;

        ResponseAPDU auth = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_ADMIN_AUTH, 0, 0, hexToBytes(adminPayloadHex)));
        if (auth.getSW() != 0x9000) {
            return err(422, "Xác thực MAC Admin thất bại", swHex(auth.getSW()), null);
        }

        byte[] padded = padTo16(infoText.getBytes(StandardCharsets.UTF_8));
        if (padded.length > Config.INFO_MAX_SIZE) {
            return err(400, "Thông tin vượt quá " + Config.INFO_MAX_SIZE + " bytes", "6700", null);
        }
        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_UPDATE_INFO, 0, 0, padded));
        if (res.getSW() != 0x9000) {
            return err(422, "Ghi thông tin AES thất bại", swHex(res.getSW()), null);
        }
        statusListener.accept("ĐÃ GHI THÔNG TIN LÊN CHIP");
        return new BridgeResult(200, "{\"ok\":true}");
    }

    public synchronized BridgeResult writeImage(String expectedUid, String adminPayloadHex, String imageHex) {
        BridgeResult chk = checkExpectedUid(expectedUid);
        if (chk != null) return chk;

        ResponseAPDU auth = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_ADMIN_AUTH, 0, 0, hexToBytes(adminPayloadHex)));
        if (auth.getSW() != 0x9000) {
            return err(422, "Xác thực MAC Admin thất bại", swHex(auth.getSW()), null);
        }

        byte[] padded = padTo16(hexToBytes(imageHex));
        if (padded.length > Config.IMG_MAX_SIZE) {
            return err(400, "Ảnh vượt quá " + Config.IMG_MAX_SIZE + " bytes", "6700", null);
        }
        int offset = 0;
        while (offset < padded.length) {
            int len = Math.min(IMG_CHUNK_SIZE, padded.length - offset);
            byte[] chunk = Arrays.copyOfRange(padded, offset, offset + len);
            ResponseAPDU res = activeSlot.simulator.transmitCommand(
                    new CommandAPDU(CLA, Config.INS_UPDATE_IMG, (offset >> 8) & 0xFF, offset & 0xFF, chunk));
            if (res.getSW() != 0x9000) {
                return err(422, "Ghi ảnh AES thất bại", swHex(res.getSW()), null);
            }
            offset += len;
        }
        statusListener.accept("ĐÃ GHI ẢNH LÊN CHIP");
        return new BridgeResult(200, "{\"ok\":true}");
    }

    public synchronized BridgeResult readAll(String expectedUid, String pin, boolean includeImage) {
        BridgeResult v = verifyPin(expectedUid, pin);
        if (v.httpStatus != 200) return v;

        String infoText = "";
        ResponseAPDU resInfo = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_GET_INFO, 0, 0, 240));
        if (resInfo.getSW() == 0x9000) {
            infoText = new String(resInfo.getData(), StandardCharsets.UTF_8).replace("\0", "").trim();
        } else if (resInfo.getSW() != 0x6A83) {
            return err(422, "Đọc thông tin trên thẻ thất bại", swHex(resInfo.getSW()), null);
        }

        String imageHex = "";
        if (includeImage) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int offset = 0;
            while (true) {
                ResponseAPDU resImg = activeSlot.simulator.transmitCommand(
                        new CommandAPDU(CLA, Config.INS_GET_IMG, (offset >> 8) & 0xFF, offset & 0xFF, IMG_CHUNK_SIZE));
                if (resImg.getSW() == 0x6A86 || resImg.getSW() == 0x6A83) break;
                if (resImg.getSW() != 0x9000) break;
                byte[] chunk = resImg.getData();
                if (chunk.length == 0) break;
                baos.write(chunk, 0, chunk.length);
                offset += chunk.length;
                if (chunk.length < IMG_CHUNK_SIZE) break;
            }
            imageHex = bytesToHex(baos.toByteArray());
        }

        int bal = 0;
        ResponseAPDU resBal = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_GET_BALANCE, 0, 0, 2));
        if (resBal.getSW() == 0x9000 && resBal.getData().length >= 2) {
            bal = ((resBal.getData()[0] & 0xFF) << 8) | (resBal.getData()[1] & 0xFF);
        }

        statusListener.accept("ĐÃ ĐỌC DỮ LIỆU CHIP (" + activeSlot.cardUid + ")");
        return new BridgeResult(200,
                "{\"infoText\":\"" + escapeJson(infoText) + "\"," +
                        "\"imageHex\":\"" + imageHex + "\"," +
                        "\"balance\":" + bal + "}");
    }

    public synchronized BridgeResult signChallenge(String expectedUid, String challengeHex) {
        BridgeResult chk = checkExpectedUid(expectedUid);
        if (chk != null) return chk;

        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_AUTH_DOOR, 0, 0, hexToBytes(challengeHex), 128));
        if (res.getSW() != 0x9000) {
            return err(422, "Ký thử thách RSA thất bại", swHex(res.getSW()), null);
        }
        statusListener.accept("ĐÃ KÝ RSA XÁC THỰC CỬA");
        return new BridgeResult(200, "{\"signatureHex\":\"" + bytesToHex(res.getData()) + "\"}");
    }

    public synchronized BridgeResult credit(String expectedUid, String payloadHex) {
        BridgeResult chk = checkExpectedUid(expectedUid);
        if (chk != null) return chk;

        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_CREDIT, 0, 0, hexToBytes(payloadHex), 18));
        if (res.getSW() != 0x9000) {
            return err(422, "Nạp tiền vào chip thất bại", swHex(res.getSW()), null);
        }
        byte[] d = res.getData();
        short bal = (short) (((d[0] & 0xFF) << 8) | (d[1] & 0xFF));
        String macHex = bytesToHex(Arrays.copyOfRange(d, 2, 18));
        statusListener.accept("NẠP VÍ CHIP -> SỐ DƯ: " + bal + "đ");
        return new BridgeResult(200, "{\"balance\":" + bal + ",\"receiptMacHex\":\"" + macHex + "\"}");
    }

    public synchronized BridgeResult debit(String expectedUid, String pin, String payloadHex) {
        BridgeResult v = verifyPin(expectedUid, pin);
        if (v.httpStatus != 200) return v;

        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_PAY_OFFLINE, 0, 0, hexToBytes(payloadHex), 18));
        if (res.getSW() != 0x9000) {
            return err(422, res.getSW() == 0x6985 ? "Số dư trên thẻ không đủ" : "Thanh toán thất bại",
                    swHex(res.getSW()), null);
        }
        byte[] d = res.getData();
        short bal = (short) (((d[0] & 0xFF) << 8) | (d[1] & 0xFF));
        String macHex = bytesToHex(Arrays.copyOfRange(d, 2, 18));
        statusListener.accept("THANH TOÁN VÍ CHIP -> CÒN " + bal + "đ");
        return new BridgeResult(200, "{\"balance\":" + bal + ",\"receiptMacHex\":\"" + macHex + "\"}");
    }

    public synchronized BridgeResult balance(String expectedUid, String pin) {
        BridgeResult v = verifyPin(expectedUid, pin);
        if (v.httpStatus != 200) return v;

        ResponseAPDU res = activeSlot.simulator.transmitCommand(
                new CommandAPDU(CLA, Config.INS_GET_BALANCE, 0, 0, 2));
        if (res.getSW() != 0x9000) {
            return err(422, "Đọc số dư thất bại", swHex(res.getSW()), null);
        }
        byte[] d = res.getData();
        short bal = (short) (((d[0] & 0xFF) << 8) | (d[1] & 0xFF));
        return new BridgeResult(200, "{\"balance\":" + bal + "}");
    }

    // =========================================================================
    // HELPERS (Khớp 100% CardCrypto & CardGatewaySigner bên Spring Boot)
    // =========================================================================
    private BridgeResult checkExpectedUid(String expectedUid) {
        if (activeSlot == null) {
            return err(409, "Chưa có thẻ nào trên đầu đọc", "6985", null);
        }
        if (expectedUid != null && !expectedUid.trim().isEmpty()
                && !activeSlot.cardUid.equalsIgnoreCase(expectedUid.trim())) {
            return err(409, "Thẻ trên đầu đọc (" + activeSlot.cardUid + ") không khớp thẻ yêu cầu (" + expectedUid + ")",
                    "6985", null);
        }
        return null;
    }

    private int getTriesRemaining() {
        ResponseAPDU r = activeSlot.simulator.transmitCommand(new CommandAPDU(CLA, Config.INS_GET_TRIES, 0, 0, 1));
        return r.getSW() == 0x9000 ? (r.getData()[0] & 0xFF) : 0;
    }

    public static String signGateway(long ts, String method, String path, byte[] body) throws Exception {
        String canonical = ts + "\n" + method.toUpperCase() + "\n" + path + "\n" + sha256Hex(body);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(GATEWAY_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    public static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return bytesToHex(md.digest(data == null ? new byte[0] : data));
    }

    private static String fingerprint(byte[] mod, byte[] exp) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(stripLeadingZero(mod));
            md.update(stripLeadingZero(exp));
            return bytesToHex(Arrays.copyOf(md.digest(), 8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] stripLeadingZero(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) i++;
        return Arrays.copyOfRange(b, i, b.length);
    }

    private static byte[] padTo16(byte[] in) {
        int rem = in.length % 16;
        int pad = rem == 0 ? 0 : (16 - rem);
        byte[] out = new byte[in.length + pad];
        System.arraycopy(in, 0, out, 0, in.length);
        return out;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        String s = hex.trim();
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String swHex(int sw) {
        return String.format("%04X", sw);
    }

    private static BridgeResult err(int status, String msg, String sw, Integer tries) {
        StringBuilder sb = new StringBuilder("{\"message\":\"").append(escapeJson(msg)).append("\"");
        if (sw != null) sb.append(",\"sw\":\"").append(sw).append("\"");
        if (tries != null) sb.append(",\"pinTriesRemaining\":").append(tries);
        sb.append("}");
        return new BridgeResult(status, sb.toString());
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String readStream(InputStream is) throws Exception {
        if (is == null) return "";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = is.read(buf)) != -1) baos.write(buf, 0, n);
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }
}