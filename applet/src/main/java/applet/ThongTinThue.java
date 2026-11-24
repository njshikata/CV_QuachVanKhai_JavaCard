package applet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class ThongTinThue {
    private final Cipher aesCipher;
    private final AESKey aesKey;
    private final byte[] userInfo;
    private short userInfoLen;
    private final byte[] userImage;
    private short userImageLen;

    public ThongTinThue() {
        userInfo = new byte[Config.INFO_MAX_SIZE];
        userImage = new byte[Config.IMG_MAX_SIZE];
        userInfoLen = 0;
        userImageLen = 0;

        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(Config.AES_DATA_KEY, (short) 0);
        // Dùng ECB để đọc/ghi ảnh theo chunk bất kỳ (bội số của 16) không bị lệch IV
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    }

    // Chỉ Backend Admin (đã xác thực MAC) mới được gọi
    public void updateInfo(APDU apdu, short len) {
        if (len == 0 || (len % 16) != 0 || len > Config.INFO_MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] buffer = apdu.getBuffer();
        JCSystem.beginTransaction();
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        userInfoLen = aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, userInfo, (short) 0);
        JCSystem.commitTransaction();
    }

    // Yêu cầu xác thực PIN mới được đọc
    public void getInfo(APDU apdu, MaPin maPin) {
        if (!maPin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (userInfoLen == 0) ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);

        byte[] buffer = apdu.getBuffer();
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        short decLen = aesCipher.doFinal(userInfo, (short) 0, userInfoLen, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, decLen);
    }

    // Chỉ Backend Admin (đã xác thực MAC) mới được gọi
    public void updateImage(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        short offset = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);

        if (len == 0 || (len % 16) != 0 || (offset % 16) != 0 || (short) (offset + len) > Config.IMG_MAX_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        JCSystem.beginTransaction();
        if (offset == 0) userImageLen = 0;
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, len, userImage, offset);
        if ((short) (offset + len) > userImageLen) {
            userImageLen = (short) (offset + len);
        }
        JCSystem.commitTransaction();
    }

    // Yêu cầu xác thực PIN mới được đọc ảnh
    public void getImage(APDU apdu, MaPin maPin) {
        if (!maPin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        short getOff = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);

        if (getOff >= userImageLen || (getOff % 16) != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short le = apdu.setOutgoing();
        if (le == 0 || le > (short) 240) {
            le = (short) 240; // Giới hạn tối đa 240 byte mỗi chunk (bội số của 16)
        }
        if ((short) (getOff + le) > userImageLen) {
            le = (short) (userImageLen - getOff);
        }
        if ((le % 16) != 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        short decLen = aesCipher.doFinal(userImage, getOff, le, buffer, (short) 0);

        apdu.setOutgoingLength(decLen);
        apdu.sendBytes((short) 0, decLen);
    }
}