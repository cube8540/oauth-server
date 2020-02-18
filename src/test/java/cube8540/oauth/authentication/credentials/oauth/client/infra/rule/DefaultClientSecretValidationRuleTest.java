package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 패스워드 유효성 검사 테스트")
class DefaultClientSecretValidationRuleTest {

    private DefaultClientSecretValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientSecretValidationRule();
    }

    @Nested
    @DisplayName("클라이언트의 패스워드가 null 일시")
    class WhenClientSecretIsNull {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);
        }

        @Test
        @DisplayName("유효성 검사시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트의 패스워드가 null이 아닐시")
    class WhenClientSecretIsNotNull{
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            String secret = "client_secret";

            this.client = mock(OAuth2Client.class);
            when(client.getSecret()).thenReturn(secret);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldReturnTrue() {
            assertTrue(rule.isValid(client));
        }
    }

}