package applet;

import javacard.framework.*;
import javacard.security.*;

public class RaVaoRSA {
    private final Signature rsaSig;
    private final KeyPair rsaKeyPair;

    public RaVaoRSA() {
        rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        rsaKeyPair.genKeyPair();
        rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
    }

    // Ký challenge từ đầu đọc cửa / tủ đồ bằng Private Key trên thẻ
    public void authDoor(APDU apdu, short len) {
        if (len == 0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        byte[] buffer = apdu.getBuffer();

        rsaSig.init(rsaKeyPair.getPrivate(), Signature.MODE_SIGN);
        short sigLen = rsaSig.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    // Xuất Public Key Modulus (128 bytes)
    public void getPublicKeyModulus(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        RSAPublicKey pubKey = (RSAPublicKey) rsaKeyPair.getPublic();
        short modLen = pubKey.getModulus(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, modLen);
    }

    // Xuất Public Key Exponent (thường 3 bytes: 01 00 01)
    public void getPublicKeyExponent(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        RSAPublicKey pubKey = (RSAPublicKey) rsaKeyPair.getPublic();
        short expLen = pubKey.getExponent(buffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, expLen);
    }
}