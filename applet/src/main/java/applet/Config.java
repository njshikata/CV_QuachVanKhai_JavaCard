package applet;

public final class Config {
    // --- ADMIN SESSION ---
    public static final byte INS_ADMIN_AUTH   = (byte) 0x10; // Mở phiên Admin bằng MAC (tự xóa khi rút thẻ)

    // --- PIN ---
    public static final byte INS_VERIFY_PIN   = (byte) 0x20;
    public static final byte INS_CHANGE_PIN   = (byte) 0x24;
    public static final byte INS_UNBLOCK_PIN  = (byte) 0x26; // Cần Admin MAC
    public static final byte INS_GET_TRIES    = (byte) 0x28;
    public static final byte INS_RESET_PIN    = (byte) 0x2A; // Cần Admin MAC

    // --- THÔNG TIN & ẢNH (AES-128) ---
    public static final byte INS_UPDATE_INFO  = (byte) 0x50; // Cần Admin Session
    public static final byte INS_GET_INFO     = (byte) 0x51; // Cần PIN
    public static final byte INS_UPDATE_IMG   = (byte) 0x52; // Cần Admin Session
    public static final byte INS_GET_IMG      = (byte) 0x53; // Cần PIN

    // --- RA VÀO / TỦ ĐỒ (RSA-1024) ---
    public static final byte INS_AUTH_DOOR    = (byte) 0x80; // Ký challenge
    public static final byte INS_GET_PUB_MOD  = (byte) 0x81; // Xuất Public Key Modulus
    public static final byte INS_GET_PUB_EXP  = (byte) 0x82; // Xuất Public Key Exponent

    // --- THANH TOÁN (AES-MAC 128) ---
    public static final byte INS_CREDIT       = (byte) 0x30; // Nạp tiền (Admin MAC)
    public static final byte INS_PAY_OFFLINE  = (byte) 0x32; // Trừ tiền (PIN + MAC)
    public static final byte INS_GET_BALANCE  = (byte) 0x34; // Xem số dư (Cần PIN)

    // --- THÔNG SỐ KỸ THUẬT ---
    public static final byte PIN_MAX_TRIES    = (byte) 5;
    public static final byte PIN_MIN_LEN      = (byte) 4;
    public static final byte PIN_MAX_LEN      = (byte) 8;
    public static final byte HASH_LEN         = (byte) 32;
    public static final short MAC_LEN         = (short) 16;
    public static final short INFO_MAX_SIZE   = (short) 240; // Vừa 1 gói Short APDU & chia hết cho 16
    public static final short IMG_MAX_SIZE    = (short) 3072;

    // Khóa riêng cho mã hóa dữ liệu AES (Thông tin + Ảnh)
    public static final byte[] AES_DATA_KEY = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    // Khóa riêng cho ổ khóa Admin & Thanh toán MAC (Khớp app.card.mac-admin-key-hex)
    public static final byte[] MAC_ADMIN_KEY = {
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
}