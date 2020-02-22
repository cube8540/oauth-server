package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트명 유효성 검사 테스트")
class DefaultClientNameValidationRuleTest {

    private DefaultClientNameValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientNameValidationRule();
    }

    @Nested
    @DisplayName("클라이언트명이 null일시")
    class WhenClientNameIsNull {

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
    @DisplayName("클라이언트명이 null이 아닐시")
    class WhenClientNameIsNotNull {
        private OAuth2Client client;

        @BeforeEach
        void setup() {
            String clientName = "client name";

            this.client = mock(OAuth2Client.class);
            when(client.getClientName()).thenReturn(clientName);
        }

        @Test
        @DisplayName("유효성 검사시 true가 반환되어야 한다.")
        void shouldReturnsTrue() {
            assertTrue(rule.isValid(client));
        }
    }
}