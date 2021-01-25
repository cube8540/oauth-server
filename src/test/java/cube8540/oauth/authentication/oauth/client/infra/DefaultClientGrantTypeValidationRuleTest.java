package cube8540.oauth.authentication.oauth.client.infra;

import cube8540.oauth.authentication.oauth.client.domain.OAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 인증 타입 유효성 검사 클래스 테스트")
class DefaultClientGrantTypeValidationRuleTest {

    private DefaultClientGrantTypeValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientGrantTypeValidationRule();
    }

    @Test
    @DisplayName("클라이언트의 인증 타입이 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void clientGrantTypeIsNullValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getGrantTypes()).thenReturn(null);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트의 인증 타입이 빈 배열일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void clientGrantTypeIsEmptyValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getGrantTypes()).thenReturn(Collections.emptySet());

        assertFalse(rule.isValid(client));
    }
}