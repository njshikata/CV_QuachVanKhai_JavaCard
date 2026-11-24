package applet;

import javacard.framework.*;
import javacard.security.*;

public class MaPin {
    private final OwnerPIN pin;
    private final MessageDigest sha256;
    private final byte[] ramBuffer;
    private final byte[] defaultPinHash; // Lưu bản hash SHA-256 thay vì plaintext

    public MaPin(byte[] defaultPin, short defOffset, short defLen) {
        ramBuffer = JCSystem.makeTransientByteArray(Config.HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        pin = new OwnerPIN(Config.PIN_MAX_TRIES, Config.HASH_LEN);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        defaultPinHash = new byte[Config.HASH_LEN];
        sha256.doFinal(defaultPin, defOffset, defLen, defaultPinHash, (short) 0);
        pin.update(defaultPinHash, (short) 0, Config.HASH_LEN);
    }

    public void verify(byte[] inBuffer, short inOffset, short inLen) {
        if (pin.getTriesRemaining() == (byte) 0) {
            ISOException.throwIt((short) 0x6983); // Khóa cứng sau 5 lần sai
        }
        if (inLen < Config.PIN_MIN_LEN || inLen > Config.PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        sha256.reset();
        sha256.doFinal(inBuffer, inOffset, inLen, ramBuffer, (short) 0);
        if (!pin.check(ramBuffer, (short) 0, Config.HASH_LEN)) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    public void change(byte[] inBuffer, short inOffset, short inLen) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (inLen < Config.PIN_MIN_LEN || inLen > Config.PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        sha256.reset();
        sha256.doFinal(inBuffer, inOffset, inLen, ramBuffer, (short) 0);
        pin.update(ramBuffer, (short) 0, Config.HASH_LEN);
    }

    public void resetToDefault() {
        pin.update(defaultPinHash, (short) 0, Config.HASH_LEN);
        pin.resetAndUnblock();
    }

    public void unblock() { pin.resetAndUnblock(); }
    public byte getTriesRemaining() { return pin.getTriesRemaining(); }
    public boolean isValidated() { return pin.isValidated(); }
}