package cube8540.oauth.authentication.credentials.oauth.client.infra.rule;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2Client;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 클라이언트 아이디 유효성 검사 클래스 테스트")
class DefaultClientIdValidationRuleTest {

    private static final String RAW_CLIENT_LESS_THEN_ALLOWED_LENGTH = "oauth";
    private static final OAuth2ClientId CLIENT_LESS_THEN_ALLOWED_LENGTH = new OAuth2ClientId(RAW_CLIENT_LESS_THEN_ALLOWED_LENGTH);
    private static final String RAW_CLIENT_GRATER_THEN_ALLOWED_LENGTH = "oauth-client-id-oauth-client-id-id";
    private static final OAuth2ClientId CLIENT_GRATER_THEN_ALLOWED_LENGTH = new OAuth2ClientId(RAW_CLIENT_GRATER_THEN_ALLOWED_LENGTH);
    private static final String RAW_CLIENT_WITH_NOT_ALLOWED_SPECIAL_CHARACTER = "oauth-client-id#";
    private static final OAuth2ClientId CLIENT_WITH_NOT_ALLOWED_SPECIAL_CHARACTER = new OAuth2ClientId(RAW_CLIENT_WITH_NOT_ALLOWED_SPECIAL_CHARACTER);

    private DefaultClientIdValidationRule rule;

    @BeforeEach
    void setup() {
        this.rule = new DefaultClientIdValidationRule();
    }

    @Test
    @DisplayName("클라이언트 아이디가 허용되는 길이보다 짧을시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void clientIdLessThenAllowedLengthValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getClientId()).thenReturn(CLIENT_LESS_THEN_ALLOWED_LENGTH);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트 이이디가 허용되는 길이보다 길시 유효성 검사 결과는 false 가 반환된어야 한다.")
    void clientIdGraterThenAllowedLengthValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getClientId()).thenReturn(CLIENT_GRATER_THEN_ALLOWED_LENGTH);

        assertFalse(rule.isValid(client));
    }

    @Test
    @DisplayName("클라이언트 아이디에 허용되지 않는 특수문자가 포함되어 있을시 유효성 검사 결과는 false 가 반환되어야 한다.")
    void clientIdIncludeNotAllowedSpacialCharacterValidationShouldReturnsFalse() {
        OAuth2Client client = mock(OAuth2Client.class);

        when(client.getClientId()).thenReturn(CLIENT_WITH_NOT_ALLOWED_SPECIAL_CHARACTER);

        assertFalse(rule.isValid(client));
    }
}