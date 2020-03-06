package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 패스워드 유효성 검사 테스트")
class DefaultClientSecretValidationRuleTest {

    private DefaultClientSecretValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientSecretValidationRule();
    }

    @Test
    @DisplayName("클라이언트의 패스워드가 null 일시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void clientSecretIsNullValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getSecret()).thenReturn(null);

        assertFalse(rule.isValid(client));
    }

}