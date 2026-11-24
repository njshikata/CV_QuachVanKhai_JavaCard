package applet;

import javacard.framework.*;
import javacard.security.*;

public class ThanhToanMAC {
    private short balance;
    private final Signature macSig;
    private final AESKey macKey;
    private final byte[] receiptBuffer;

    public ThanhToanMAC() {
        balance = 0;
        receiptBuffer = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
        macKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        macKey.setKey(Config.MAC_ADMIN_KEY, (short) 0);
        macSig = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD, false);
    }

    public boolean verifyMAC(byte[] buffer, short dataOff, short dataLen, short macOff) {
        if (dataLen != (short) 16) return false;
        macSig.init(macKey, Signature.MODE_VERIFY);
        return macSig.verify(buffer, dataOff, dataLen, buffer, macOff, Config.MAC_LEN);
    }

    private void sendSignedReceipt(APDU apdu, short newBalance, short amount) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayFillNonAtomic(receiptBuffer, (short) 0, (short) 16, (byte) 0x00);
        Util.setShort(receiptBuffer, (short) 0, newBalance);
        Util.setShort(receiptBuffer, (short) 2, amount);

        Util.setShort(buffer, (short) 0, newBalance);
        macSig.init(macKey, Signature.MODE_SIGN);
        short macLen = macSig.sign(receiptBuffer, (short) 0, (short) 16, buffer, (short) 2);
        apdu.setOutgoingAndSend((short) 0, (short) (2 + macLen));
    }

    public void processCredit(APDU apdu, short len) {
        if (len != (short) 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] buffer = apdu.getBuffer();

        if (!verifyMAC(buffer, ISO7816.OFFSET_CDATA, (short) 16, (short) (ISO7816.OFFSET_CDATA + 16))) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short amount = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (amount <= 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        if ((short) (balance + amount) > 30000 || (short) (balance + amount) < 0) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        JCSystem.beginTransaction();
        balance = (short) (balance + amount);
        JCSystem.commitTransaction();

        sendSignedReceipt(apdu, balance, amount);
    }

    public void processDebit(APDU apdu, short len, MaPin maPin) {
        if (!maPin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (len != (short) 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] buffer = apdu.getBuffer();

        if (!verifyMAC(buffer, ISO7816.OFFSET_CDATA, (short) 16, (short) (ISO7816.OFFSET_CDATA + 16))) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short amount = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (amount <= 0) ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        if (balance < amount) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        JCSystem.beginTransaction();
        balance = (short) (balance - amount);
        JCSystem.commitTransaction();

        sendSignedReceipt(apdu, balance, amount);
    }

    public void getBalance(APDU apdu, MaPin maPin) {
        if (!maPin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buffer = apdu.getBuffer();
        Util.setShort(buffer, (short) 0, balance);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }
}