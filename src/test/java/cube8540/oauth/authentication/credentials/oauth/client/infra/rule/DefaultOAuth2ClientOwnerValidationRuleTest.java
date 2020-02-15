package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 소유자 유효성 검사 클래스 테스트")
class DefaultOAuth2ClientOwnerValidationRuleTest {

    private DefaultOAuth2ClientOwnerValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultOAuth2ClientOwnerValidationRule();
    }

    @Nested
    @DisplayName("클라이언트의 소유자가 null일시")
    class WhenClientOwnerIsNull {

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
    @DisplayName("클라이언트 소유자가 null이 아닐시")
    class WhenClientOwnerIsNotNull {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);

            when(client.getOwner()).thenReturn(new UserEmail("email@email.com"));
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldReturnsTrue() {
            assertTrue(rule.isValid(client));
        }
    }

}