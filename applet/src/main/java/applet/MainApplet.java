package applet;

import javacard.framework.*;

public class MainApplet extends Applet {

	private final MaPin maPin;
	private final ThongTinThue thongTin;
	private final RaVaoRSA raVao;
	private final ThanhToanMAC thanhToan;
	private final boolean[] adminSession;

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new MainApplet();
	}

	private MainApplet() {
		byte[] defaultPin = {'2', '7', '0', '3'};
		maPin = new MaPin(defaultPin, (short) 0, (short) 4);
		thongTin = new ThongTinThue();
		raVao = new RaVaoRSA();
		thanhToan = new ThanhToanMAC();
		adminSession = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		register();
	}

	private void requireAdminMAC(byte[] buffer, short len) {
		if (len != (short) 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!thanhToan.verifyMAC(buffer, ISO7816.OFFSET_CDATA, (short) 16, (short) (ISO7816.OFFSET_CDATA + 16))) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
	}

	public void process(APDU apdu) {
		if (selectingApplet()) return;
		byte[] buffer = apdu.getBuffer();
		byte ins = buffer[ISO7816.OFFSET_INS];

		switch (ins) {
			// --- MỞ PHIÊN ADMIN BẰNG MAC ---
			case Config.INS_ADMIN_AUTH: {
				short len = apdu.setIncomingAndReceive();
				requireAdminMAC(buffer, len);
				adminSession[0] = true;
				break;
			}

			// --- PIN ---
			case Config.INS_VERIFY_PIN: {
				short len = apdu.setIncomingAndReceive();
				maPin.verify(buffer, ISO7816.OFFSET_CDATA, len);
				break;
			}
			case Config.INS_CHANGE_PIN: {
				short len = apdu.setIncomingAndReceive();
				maPin.change(buffer, ISO7816.OFFSET_CDATA, len);
				break;
			}
			case Config.INS_UNBLOCK_PIN: {
				short len = apdu.setIncomingAndReceive();
				requireAdminMAC(buffer, len);
				maPin.unblock();
				break;
			}
			case Config.INS_RESET_PIN: {
				short len = apdu.setIncomingAndReceive();
				requireAdminMAC(buffer, len);
				maPin.resetToDefault();
				break;
			}
			case Config.INS_GET_TRIES:
				buffer[0] = maPin.getTriesRemaining();
				apdu.setOutgoingAndSend((short) 0, (short) 1);
				break;

			// --- THÔNG TIN & ẢNH (GHI: CHỈ ADMIN | ĐỌC: CẦN PIN) ---
			case Config.INS_UPDATE_INFO: {
				if (!adminSession[0]) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				short len = apdu.setIncomingAndReceive();
				thongTin.updateInfo(apdu, len);
				break;
			}
			case Config.INS_GET_INFO:
				thongTin.getInfo(apdu, maPin);
				break;
			case Config.INS_UPDATE_IMG: {
				if (!adminSession[0]) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
				short len = apdu.setIncomingAndReceive();
				thongTin.updateImage(apdu, len);
				break;
			}
			case Config.INS_GET_IMG:
				thongTin.getImage(apdu, maPin);
				break;

			// --- RA VÀO / TỦ ĐỒ (RSA) ---
			case Config.INS_AUTH_DOOR: {
				short len = apdu.setIncomingAndReceive();
				raVao.authDoor(apdu, len);
				break;
			}
			case Config.INS_GET_PUB_MOD:
				raVao.getPublicKeyModulus(apdu);
				break;
			case Config.INS_GET_PUB_EXP:
				raVao.getPublicKeyExponent(apdu);
				break;

			// --- THANH TOÁN (MAC) ---
			case Config.INS_CREDIT: {
				short len = apdu.setIncomingAndReceive();
				thanhToan.processCredit(apdu, len);
				break;
			}
			case Config.INS_PAY_OFFLINE: {
				short len = apdu.setIncomingAndReceive();
				thanhToan.processDebit(apdu, len, maPin);
				break;
			}
			case Config.INS_GET_BALANCE:
				thanhToan.getBalance(apdu, maPin);
				break;

			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}