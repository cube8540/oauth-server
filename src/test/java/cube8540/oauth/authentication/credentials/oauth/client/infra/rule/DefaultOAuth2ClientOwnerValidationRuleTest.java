package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 소유자 유효성 검사 클래스 테스트")
class DefaultOAuth2ClientOwnerValidationRuleTest {

    private DefaultOAuth2ClientOwnerValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultOAuth2ClientOwnerValidationRule();
    }

    @Test
    @DisplayName("클라이언트의 소유자가 null 일시 유효성 검사 결과는 false 가 반환되여야 한다.")
    void clientOwnerNullValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getOwner()).thenReturn(null);

        assertFalse(rule.isValid(client));
    }

}