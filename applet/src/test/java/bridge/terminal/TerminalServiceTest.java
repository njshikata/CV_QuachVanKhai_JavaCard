package bridge.terminal;

import bridge.card.CardService;
import bridge.card.CardSwException;
import bridge.port.SimulatorCardPort;
import bridge.server.GatewayApi;
import bridge.server.ServerRejectedException;
import bridge.util.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Máy đầu cuối chạy với CHIP GIẢ LẬP THẬT (applet MainApplet trên jcardsim) + server giả
 * làm đúng việc của server thật: verify RSA bằng public key, sinh payload AES-MAC, kiểm MAC biên lai.
 */
class TerminalServiceTest {

    private static final String PIN = "2703";
    private static final byte[] MAC_KEY = Hex.decode("1112131415161718191A1B1C1D1E1F20");

    private SimulatorCardPort port;
    private CardService card;
    private FakeServer server;
    private TerminalService terminal;

    @BeforeEach
    void setUp() {
        port = new SimulatorCardPort();
        card = new CardService(port);
        server = new FakeServer(card.publicKey());
        terminal = new TerminalService(card, server, "TEST-GATE");
    }

    // ============================ RA VÀO – chỉ cần PIN ============================
    @Test
    void swipeWithCorrectPinGranted() {
        Map<String, Object> r = terminal.swipe("door_in", PIN, "  ");
        assertEquals(Boolean.TRUE, r.get("granted"), String.valueOf(r.get("message")));
        assertEquals(1, server.challenges);
        assertEquals(Boolean.TRUE, server.lastChallenge.get("pinVerified"));
        assertEquals("DOOR_IN", server.lastChallenge.get("action"));
        assertNull(server.lastChallenge.get("note"));
        assertEquals(5, card.pinTries()); // đúng PIN => không mất lượt
    }

    @Test
    void swipeWrongPinDeniedWithoutAskingServerForChallenge() {
        Map<String, Object> r = terminal.swipe("LOCKER_OPEN", "1111", "tu 3");
        assertEquals(Boolean.FALSE, r.get("granted"));
        assertEquals(4, r.get("pinTriesRemaining"));
        assertTrue(r.get("message").toString().contains("còn 4"));
        assertEquals(0, server.challenges);
        assertEquals(1, server.pinFailed.size());
        assertEquals(4, server.pinFailed.get(0).get("pinTriesRemaining"));
        assertEquals("tu 3", server.pinFailed.get(0).get("note"));
    }

    @Test
    void fiveWrongPinsBlockCard() {
        for (int i = 0; i < 4; i++) terminal.swipe("DOOR_IN", "0000", null);
        Map<String, Object> r = terminal.swipe("DOOR_IN", "0000", null);
        assertEquals(0, r.get("pinTriesRemaining"));
        assertTrue(r.get("message").toString().contains("khóa"));
        // Kể cả đúng PIN cũng bị từ chối khi thẻ đã khóa
        Map<String, Object> again = terminal.swipe("DOOR_IN", PIN, null);
        assertEquals(Boolean.FALSE, again.get("granted"));
        assertEquals(0, server.challenges);
    }

    @Test
    void wrongPinStillDeniedWhenServerUnreachable() {
        server.failPinFailed = true;
        Map<String, Object> r = terminal.swipe("DOOR_OUT", "9999", null);
        assertEquals(Boolean.FALSE, r.get("granted"));
        assertEquals(Boolean.FALSE, r.get("logged"));
    }

    @Test
    void serverDenialPassedThrough() {
        server.denyAll = "Thẻ đang bị khóa";
        Map<String, Object> r = terminal.swipe("DOOR_IN", PIN, null);
        assertEquals(Boolean.FALSE, r.get("granted"));
        assertEquals("Thẻ đang bị khóa", r.get("message"));
    }

    @Test
    void swipeInputValidation() {
        assertThrows(IllegalArgumentException.class, () -> terminal.swipe("FLY", PIN, null));
        assertThrows(IllegalArgumentException.class, () -> terminal.swipe("DOOR_IN", null, null));
        assertThrows(IllegalArgumentException.class, () -> terminal.swipe("DOOR_IN", "12a4", null));
        assertThrows(IllegalArgumentException.class, () -> terminal.swipe("DOOR_IN", "123", null));
        assertEquals(5, card.pinTries()); // PIN sai định dạng không gửi xuống chip => không mất lượt
    }

    // ============================ VÍ – bắt buộc OTP ============================
    @Test
    void creditWithOtp() {
        Map<String, Object> otp = terminal.requestWalletOtp("credit", 500);
        String rid = otp.get("requestId").toString();
        assertFalse(terminal.needsPin(rid));
        Map<String, Object> r = terminal.confirmWallet(rid, FakeServer.CODE, null);
        assertEquals(Boolean.TRUE, r.get("macValid"));
        assertEquals(500, ((Number) r.get("balance")).intValue());
        assertEquals(500, chipBalance());
        assertThrows(IllegalArgumentException.class, () -> terminal.confirmWallet(rid, FakeServer.CODE, null));
        assertEquals(500, chipBalance());
    }

    @Test
    void wrongOtpLeavesChipUntouched() {
        String rid = terminal.requestWalletOtp("CREDIT", 300).get("requestId").toString();
        ServerRejectedException e = assertThrows(ServerRejectedException.class,
                () -> terminal.confirmWallet(rid, "000000", null));
        assertTrue(e.getMessage().contains("Sai mã"));
        assertEquals(0, chipBalance());
        assertThrows(IllegalArgumentException.class, () -> terminal.confirmWallet(rid, "12345", null)); // sai định dạng
        assertThrows(IllegalArgumentException.class, () -> terminal.confirmWallet(" ", FakeServer.CODE, null));
    }

    @Test
    void debitWrongPinRetrySameOtpDebitsOnce() {
        credit(1000);
        String rid = terminal.requestWalletOtp("DEBIT", 250).get("requestId").toString();
        assertTrue(terminal.needsPin(rid));
        assertThrows(IllegalArgumentException.class, () -> terminal.confirmWallet(rid, FakeServer.CODE, null));

        TerminalService.WalletPinException e = assertThrows(TerminalService.WalletPinException.class,
                () -> terminal.confirmWallet(rid, FakeServer.CODE, "1111"));
        assertEquals(4, e.getPinTriesRemaining());
        assertTrue(e.getMessage().contains("giữ nguyên mã OTP"));
        assertEquals(1000, chipBalance());

        Map<String, Object> r = terminal.confirmWallet(rid, FakeServer.CODE, PIN);
        assertEquals(Boolean.TRUE, r.get("macValid"));
        assertEquals(750, chipBalance());
        assertEquals(1, server.receipts.size() - 1); // 1 biên lai nạp + 1 biên lai thanh toán
    }

    @Test
    void debitInsufficientBalance() {
        credit(100);
        String rid = terminal.requestWalletOtp("DEBIT", 200).get("requestId").toString();
        CardSwException e = assertThrows(CardSwException.class, () -> terminal.confirmWallet(rid, FakeServer.CODE, PIN));
        assertEquals(0x6985, e.getSw());
        assertEquals(100, chipBalance());
    }

    @Test
    void receiptLostThenResentWithoutDoubleCredit() {
        String rid = terminal.requestWalletOtp("CREDIT", 400).get("requestId").toString();
        server.failReceipts = 1;
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> terminal.confirmWallet(rid, FakeServer.CODE, null));
        assertTrue(e.getMessage().contains("ĐÃ ghi"));
        assertEquals(400, chipBalance());
        assertTrue(terminal.unsentReceipts().containsKey(rid));

        Map<String, Object> r = terminal.confirmWallet(rid, FakeServer.CODE, null); // chỉ gửi lại biên lai
        assertEquals(Boolean.TRUE, r.get("macValid"));
        assertEquals(400, chipBalance()); // KHÔNG cộng lần 2
        assertEquals(1, server.authorizeCalls);
        assertTrue(terminal.unsentReceipts().isEmpty());
    }

    @Test
    void walletInputValidation() {
        assertThrows(IllegalArgumentException.class, () -> terminal.requestWalletOtp("REFUND", 10));
        assertThrows(IllegalArgumentException.class, () -> terminal.requestWalletOtp("CREDIT", 0));
        assertThrows(IllegalArgumentException.class, () -> terminal.requestWalletOtp("CREDIT", 30001));
        assertEquals(0, server.otps.size());
    }

    @Test
    void creditOverLimitRejectedByChip() {
        credit(30000);
        String rid = terminal.requestWalletOtp("CREDIT", 1).get("requestId").toString();
        CardSwException e = assertThrows(CardSwException.class, () -> terminal.confirmWallet(rid, FakeServer.CODE, null));
        assertEquals(0x6A84, e.getSw());
        assertEquals(30000, chipBalance());
    }

    // ============================ CỤC BỘ ============================
    @Test
    void changePinThenSwipeWithNewPin() {
        assertThrows(IllegalArgumentException.class, () -> terminal.changePin(PIN, PIN));
        assertThrows(IllegalArgumentException.class, () -> terminal.changePin(PIN, "12"));
        terminal.changePin(PIN, "4321");
        assertEquals(Boolean.FALSE, terminal.swipe("DOOR_IN", PIN, null).get("granted"));
        assertEquals(Boolean.TRUE, terminal.swipe("DOOR_IN", "4321", null).get("granted"));
    }

    @Test
    void readBlankCard() {
        Map<String, Object> r = terminal.readCard(PIN);
        assertEquals(0, ((Number) r.get("balance")).intValue());
        assertNull(r.get("imageHex"));
        assertThrows(CardSwException.class, () -> terminal.readCard("1111"));
    }

    @Test
    void otherVirtualCardHasItsOwnUid() {
        String uid1 = card.cardUid();
        port.createVirtualCard();
        assertNotEquals(uid1, card.cardUid());
        // Server giả chỉ biết thẻ 1 => thẻ 2 bị từ chối chữ ký
        assertEquals(Boolean.FALSE, terminal.swipe("DOOR_IN", PIN, null).get("granted"));
    }

    // ============================ helpers ============================
    private int chipBalance() {
        return ((Number) card.balance(PIN).get("balance")).intValue();
    }

    private void credit(int amount) {
        String rid = terminal.requestWalletOtp("CREDIT", amount).get("requestId").toString();
        terminal.confirmWallet(rid, FakeServer.CODE, null);
    }

    static byte[] mac16(byte[] data16) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(MAC_KEY, "AES"), new IvParameterSpec(new byte[16]));
            return c.doFinal(data16);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Server giả – cùng quy tắc với Spring Boot (CardGatewayService / CardWalletService). */
    static class FakeServer implements GatewayApi {
        static final String CODE = "482915";
        final String uid;
        final PublicKey key;
        final SecureRandom rnd = new SecureRandom();
        final Map<String, String[]> pending = new HashMap<String, String[]>();
        final Map<String, Map<String, Object>> otps = new HashMap<String, Map<String, Object>>();
        final List<Map<String, Object>> pinFailed = new ArrayList<Map<String, Object>>();
        final List<Map<String, Object>> receipts = new ArrayList<Map<String, Object>>();
        Map<String, Object> lastChallenge;
        int challenges, authorizeCalls, failReceipts;
        boolean failPinFailed;
        String denyAll;

        FakeServer(Map<String, Object> pub) {
            uid = pub.get("cardUid").toString();
            try {
                key = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                        new BigInteger(1, Hex.decode(pub.get("modulusHex").toString())),
                        new BigInteger(1, Hex.decode(pub.get("exponentHex").toString()))));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public Map<String, Object> post(String path, Map<String, Object> body) {
            Map<String, Object> res = new LinkedHashMap<String, Object>();
            if (path.endsWith("/challenge")) {
                if (!Boolean.TRUE.equals(body.get("pinVerified"))) throw new ServerRejectedException(400, "Cần PIN");
                challenges++;
                lastChallenge = body;
                byte[] ch = new byte[16];
                rnd.nextBytes(ch);
                String id = UUID.randomUUID().toString();
                pending.put(id, new String[]{body.get("cardUid").toString(), Hex.encode(ch)});
                res.put("challengeId", id);
                res.put("challengeHex", Hex.encode(ch));
            } else if (path.endsWith("/verify")) {
                String[] p = pending.remove(body.get("challengeId").toString());
                boolean ok = p != null && p[0].equals(uid) && rsaOk(p[1], body.get("signatureHex").toString());
                if (denyAll != null) {
                    res.put("granted", false);
                    res.put("message", denyAll);
                } else {
                    res.put("granted", ok);
                    res.put("message", ok ? "Mời vào" : "Chữ ký RSA không hợp lệ");
                }
            } else if (path.endsWith("/pin-failed")) {
                if (failPinFailed) throw new IllegalStateException("Không gọi được server");
                pinFailed.add(body);
                res.put("granted", false);
            } else if (path.endsWith("/wallet/otp")) {
                String id = UUID.randomUUID().toString();
                Map<String, Object> o = new HashMap<String, Object>(body);
                otps.put(id, o);
                res.put("requestId", id);
                res.put("expiresInSeconds", 300);
                res.put("message", "Đã gửi mã");
            } else if (path.endsWith("/wallet/authorize")) {
                authorizeCalls++;
                Map<String, Object> o = otps.get(body.get("requestId").toString());
                if (o == null) throw new ServerRejectedException(400, "Mã không tồn tại");
                if (!CODE.equals(body.get("otp"))) throw new ServerRejectedException(400, "Sai mã xác nhận (còn 4 lần)");
                if (!uid.equals(body.get("cardUid"))) throw new ServerRejectedException(400, "Sai thẻ");
                if (!o.containsKey("payloadHex")) {
                    int amount = ((Number) o.get("amount")).intValue();
                    byte[] d = new byte[16];
                    rnd.nextBytes(d);
                    d[0] = (byte) (amount >> 8);
                    d[1] = (byte) amount;
                    byte[] p = Arrays.copyOf(d, 32);
                    System.arraycopy(mac16(d), 0, p, 16, 16);
                    o.put("payloadHex", Hex.encode(p));
                }
                res.put("requestId", body.get("requestId"));
                res.put("type", o.get("type"));
                res.put("amount", o.get("amount"));
                res.put("payloadHex", o.get("payloadHex"));
            } else if (path.endsWith("/wallet/receipt")) {
                if (failReceipts > 0) {
                    failReceipts--;
                    throw new IllegalStateException("Mất mạng");
                }
                Map<String, Object> o = otps.remove(body.get("requestId").toString());
                if (o == null) throw new ServerRejectedException(400, "Giao dịch chưa xác nhận");
                int bal = ((Number) body.get("balance")).intValue();
                int amount = ((Number) o.get("amount")).intValue();
                byte[] r = new byte[16];
                r[0] = (byte) (bal >> 8); r[1] = (byte) bal; r[2] = (byte) (amount >> 8); r[3] = (byte) amount;
                boolean macValid = Arrays.equals(mac16(r), Hex.decode(body.get("receiptMacHex").toString()));
                receipts.add(body);
                res.put("transactionId", receipts.size());
                res.put("type", o.get("type"));
                res.put("amount", amount);
                res.put("balance", bal);
                res.put("macValid", macValid);
            } else {
                throw new IllegalArgumentException("Không có API " + path);
            }
            return res;
        }

        private boolean rsaOk(String challengeHex, String sigHex) {
            try {
                Signature s = Signature.getInstance("SHA1withRSA");
                s.initVerify(key);
                s.update(Hex.decode(challengeHex));
                return s.verify(Hex.decode(sigHex));
            } catch (Exception e) {
                return false;
            }
        }
    }
}
