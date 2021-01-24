package cube8540.oauth.authentication.oauth.client.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.ADDED_SCOPE;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.RAW_CHANGE_SECRET;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.RAW_ENCODING_SECRET;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.RAW_SECRET;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.makePassValidatorFactory;
import static cube8540.oauth.authentication.oauth.client.domain.OAuth2ClientTestsHelper.makePasswordEncoder;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 클라이언트 테스트")
class OAuth2ClientTest {

    private OAuth2Client client;

    @BeforeEach
    void setup() {
        this.client = new OAuth2Client(RAW_CLIENT_ID, RAW_SECRET);
    }

    @Test
    @DisplayName("리다이렉트 URI 추가")
    void addRedirectUri() {
        this.client.addRedirectUri(REDIRECT_URI);

        assertTrue(client.getRedirectUris().contains(REDIRECT_URI));
    }

    @Test
    @DisplayName("리다이렉트 URI 삭제")
    void removeRedirectUri() {
        this.client.addRedirectUri(REDIRECT_URI);

        this.client.removeRedirectUri(REDIRECT_URI);

        assertFalse(client.getRedirectUris().contains(REDIRECT_URI));
    }

    @Test
    @DisplayName("클라이언트 인증 방식 추가")
    void addClientGrantType() {
        this.client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);

        assertTrue(client.getGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
    }

    @Test
    @DisplayName("클라이언트 인증 방식 삭제")
    void removeClientGrantType() {
        this.client.addGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);

        this.client.removeGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertFalse(client.getGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE));
    }

    @Test
    @DisplayName("클라이언트 스코프 추가")
    void addClientScope() {
        this.client.addScope(ADDED_SCOPE);

        assertTrue(client.getScopes().contains(ADDED_SCOPE));
    }

    @Test
    @DisplayName("클라이언트 스코프 삭제")
    void removeClientScope() {
        this.client.addScope(ADDED_SCOPE);

        this.client.removeScope(ADDED_SCOPE);
        assertFalse(client.getScopes().contains(ADDED_SCOPE));
    }

    @Test
    @DisplayName("클라이언트 패스워드 암호화")
    void clientSecretEncrypting() {
        PasswordEncoder encoder = makePasswordEncoder(RAW_SECRET, RAW_ENCODING_SECRET);

        this.client.encrypted(encoder);
        assertEquals(RAW_ENCODING_SECRET, client.getSecret());
    }

    @Test
    @DisplayName("유효 하지 않은 정보가 저장 되어 있을시")
    void clientDataInvalid() {
        OAuth2ClientValidatorFactory factory = makeErrorValidatorFactory(client);

        assertThrows(ClientInvalidException.class, () -> client.validate(factory));
    }

    @Test
    @DisplayName("모든 데이터가 유효할시")
    void clientDataAllowed() {
        OAuth2ClientValidatorFactory factory = makePassValidatorFactory(client);

        assertDoesNotThrow(() -> client.validate(factory));
    }

    @Test
    @DisplayName("이전에 사용 하던 패스워드와 서로 일치 하지 않을시")
    void whenNotMatchedExistsSecret() {
        PasswordEncoder encoder = makePasswordEncoder(RAW_SECRET, RAW_ENCODING_SECRET);

        this.client.encrypted(encoder);
        when(encoder.matches(RAW_SECRET, RAW_ENCODING_SECRET)).thenReturn(false);

        ClientAuthorizationException e = assertThrows(ClientAuthorizationException.class, () -> client.changeSecret(RAW_SECRET, RAW_CHANGE_SECRET, encoder));
        assertEquals(ClientErrorCodes.INVALID_PASSWORD, e.getCode());
    }

    @Test
    @DisplayName("패스워드 변경")
    void changeSecret() {
        PasswordEncoder encoder = makePasswordEncoder(RAW_SECRET, RAW_ENCODING_SECRET);

        this.client.encrypted(encoder);

        client.changeSecret(RAW_SECRET, RAW_CHANGE_SECRET, encoder);
        assertEquals(RAW_CHANGE_SECRET, client.getSecret());
    }
}