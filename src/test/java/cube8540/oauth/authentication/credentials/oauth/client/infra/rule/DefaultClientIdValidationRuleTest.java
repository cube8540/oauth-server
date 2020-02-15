package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 아이디 유효성 검사 클래스 테스트")
class DefaultClientIdValidationRuleTest {

    private static final String CLIENT_ID = "oauth-client-id";
    private static final String CLIENT_LESS_THEN_ALLOWED_LENGTH = "oauth";
    private static final String CLIENT_GRATER_THEN_ALLOWED_LENGTH = "oauth-client-id-oauth-client-id-id";
    private static final String CLIENT_WITH_NOT_ALLOWED_SPECIAL_CHARACTER = "oauth-client-id#";

    private DefaultClientIdValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientIdValidationRule();
    }

    @Nested
    @DisplayName("클라이언트 아이디가 허용되는 길이보다 짧을시")
    class WhenLessThenAllowedLength {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);

            when(client.getClientId()).thenReturn(new OAuth2ClientId(CLIENT_LESS_THEN_ALLOWED_LENGTH));
        }

        @Test
        @DisplayName("유효성 검사 결과시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트 아이다가 허용되는 길이보다 길시")
    class WhenGraterThenAllowedLength {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);

            when(client.getClientId()).thenReturn(new OAuth2ClientId(CLIENT_GRATER_THEN_ALLOWED_LENGTH));
        }

        @Test
        @DisplayName("유효성 검사 결과시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트 아이디에 허용되지 않은 특수문자가 포함되어 있을시")
    class WhenIncludeNotAllowedSpacialCharacterInClientId {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);

            when(client.getClientId()).thenReturn(new OAuth2ClientId(CLIENT_WITH_NOT_ALLOWED_SPECIAL_CHARACTER));
        }

        @Test
        @DisplayName("유효성 검사 결과시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("허용되는 클라이언트 아이디일시")
    class WhenAllowedClientId {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);

            when(client.getClientId()).thenReturn(new OAuth2ClientId(CLIENT_ID));
        }

        @Test
        @DisplayName("유효성 검사 결과시 true가 반환되어야 한다.")
        void shouldReturnsTrue() {
            assertTrue(rule.isValid(client));
        }
    }

}