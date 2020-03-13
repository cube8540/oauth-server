package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.token.domain.AuthorizationCodeGenerator;

import java.security.SecureRandom;
import java.util.Random;

public class DefaultAuthorizationCodeGenerator implements AuthorizationCodeGenerator {

    private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .toCharArray();

    private Random random;
    private int length;

    public DefaultAuthorizationCodeGenerator() {
        this(6);
    }

    public DefaultAuthorizationCodeGenerator(int keyLength) {
        this.random = new SecureRandom();
        this.length = keyLength;
    }


    @Override
    public String generate() {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);

        return getRandomCode(bytes);
    }

    private String getRandomCode(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i < bytes.length; i ++) {
            chars[i] = DEFAULT_CODEC[((bytes[i] & 0xFF) % DEFAULT_CODEC.length)];
        }

        return new String(chars);
    }
}
