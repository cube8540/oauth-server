package cube8540.oauth.authentication.credentials.oauth.client.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 패스워드 테스트")
class OAuth2ClientDefaultSecretTest {

    private static final String SECRET = "SECRET";
    private static final String ENCODING_SECRET = "ENCODING-SECRET";

    private OAuth2ClientSecretEncoder encoder;

    @BeforeEach
    void setup() {
        this.encoder = mock(OAuth2ClientSecretEncoder.class);
    }

    @Nested
    @DisplayName("클라이언트 패스워드 생성")
    class InitializeClientSecret {

        private OAuth2ClientDefaultSecret secret;

        @BeforeEach
        void setup() {
            this.secret = new OAuth2ClientDefaultSecret(SECRET);
        }

        @Test
        @DisplayName("인자로 받은 패스워드를 저장 해야 한다.")
        void shouldSaveGivenSecret() {
            assertEquals(SECRET, secret.getSecret());
        }

        @Test
        @DisplayName("암호화 여부는 false가 반환되어야 한다.")
        void shouldIsEncryptedReturnsFalse() {
            assertFalse(secret.isEncrypted());
        }
    }

    @Nested
    @DisplayName("패스워드 암호화")
    class EncryptedSecret {

        private OAuth2ClientDefaultSecret secret;

        @BeforeEach
        void setup() {
            this.secret = new OAuth2ClientDefaultSecret(SECRET);
            when(encoder.encode(SECRET)).thenReturn(ENCODING_SECRET);
        }

        @Test
        @DisplayName("인코딩된 패스워드를 저장해야 있어야 한다.")
        void shouldSaveEncodingSecret() {
            OAuth2ClientSecret result = secret.encrypted(encoder);
            assertEquals(ENCODING_SECRET, result.getSecret());
        }

        @Test
        @DisplayName("암호화 여부는 true가 반환되어야 한다.")
        void shouldIsEncryptedReturnsTrue() {
            OAuth2ClientSecret result = secret.encrypted(encoder);
            assertTrue(result.isEncrypted());
        }
    }

}