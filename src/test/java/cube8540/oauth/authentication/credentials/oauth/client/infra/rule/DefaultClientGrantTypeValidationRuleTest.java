package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 인증 타입 유효성 검사 클래스 테스트")
class DefaultClientGrantTypeValidationRuleTest {

    private DefaultClientGrantTypeValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientGrantTypeValidationRule();
    }

    @Nested
    @DisplayName("클라이언트의 인증 타입이 null일시")
    class WhenClientGrantTypeIsNull {
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
    @DisplayName("클라이언트의 인증 타입이 비어있을시")
    class WhenClientGrantTypeIsEmpty {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            this.client = mock(OAuth2Client.class);

            when(this.client.getGrantType()).thenReturn(Collections.emptySet());
        }

        @Test
        @DisplayName("유효성 검사시 false가 반환되어야 한다.")
        void shouldReturnsFalse() {
            assertFalse(rule.isValid(client));
        }
    }

    @Nested
    @DisplayName("클라이언트의 인증 타입이 비어있지 않을시")
    class WhenClientGrantTypeIsNotEmpty {

        private OAuth2Client client;

        @BeforeEach
        void setup() {
            Set<AuthorizationGrantType> grantTypes = new HashSet<>(Arrays.asList(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.PASSWORD));
            this.client = mock(OAuth2Client.class);

            when(this.client.getGrantType()).thenReturn(grantTypes);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldReturnsTrue() {
            assertTrue(rule.isValid(client));
        }
    }

}