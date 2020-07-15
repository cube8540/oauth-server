package cube8540.oauth.authentication.credentials.oauth.client.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientErrorCodes;
import cube8540.oauth.authentication.credentials.oauth.client.domain.exception.ClientInvalidException;
import cube8540.validator.core.ValidationError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.ADDED_SCOPE;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.RAW_CHANGE_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.RAW_ENCODING_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.RAW_SECRET;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.makeErrorValidationRule;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.makePassValidationRule;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.makePasswordEncoder;
import static cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientTestsHelper.makeValidationPolicy;
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
    @DisplayName("클라이언트 아이디가 유효 하지 않을때 유효성 체크")
    void validationWhenClientIdNotAllowed() {
        ValidationError error = new ValidationError("clientId", "invalid client id");
        OAuth2ClientValidatePolicy policy = makeValidationPolicy().clientIdRule(makeErrorValidationRule(this.client, error))
                .secretRule(makePassValidationRule(this.client))
                .clientNameRule(makePassValidationRule(this.client))
                .grantTypeRule(makePassValidationRule(this.client))
                .scopeRule(makePassValidationRule(this.client))
                .ownerRule(makePassValidationRule(this.client)).build();

        ClientInvalidException e = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
        assertTrue(e.getErrors().contains(error));
    }

    @Test
    @DisplayName("클라이언트 패스워드가 유효 하지 않을떄 유효성 체크")
    void validationWhenClientSecretNotAllowed() {
        ValidationError error = new ValidationError("secret", "invalid secret");
        OAuth2ClientValidatePolicy policy = makeValidationPolicy().clientIdRule(makePassValidationRule(this.client))
                .secretRule(makeErrorValidationRule(this.client, error))
                .clientNameRule(makePassValidationRule(this.client))
                .grantTypeRule(makePassValidationRule(this.client))
                .scopeRule(makePassValidationRule(this.client))
                .ownerRule(makePassValidationRule(this.client)).build();

        ClientInvalidException e = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
        assertTrue(e.getErrors().contains(error));
    }

    @Test
    @DisplayName("클라이언트명이 유효 하지 않을떄 유효성 체크")
    void validationWhenClientNameNotAllowed() {
        ValidationError error = new ValidationError("clientName", "invalid client name");
        OAuth2ClientValidatePolicy policy = makeValidationPolicy().clientIdRule(makePassValidationRule(this.client))
                .secretRule(makePassValidationRule(this.client))
                .clientNameRule(makeErrorValidationRule(this.client, error))
                .grantTypeRule(makePassValidationRule(this.client))
                .scopeRule(makePassValidationRule(this.client))
                .ownerRule(makePassValidationRule(this.client)).build();

        ClientInvalidException e = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
        assertTrue(e.getErrors().contains(error));
    }

    @Test
    @DisplayName("클라이언트 인가 방식이 유효 하지 않을떄 유효성 체크")
    void validationWhenClientGrantTypeNotAllowed() {
        ValidationError error = new ValidationError("grantType", "invalid grant type");
        OAuth2ClientValidatePolicy policy = makeValidationPolicy().clientIdRule(makePassValidationRule(this.client))
                .secretRule(makePassValidationRule(this.client))
                .clientNameRule(makePassValidationRule(this.client))
                .grantTypeRule(makeErrorValidationRule(this.client, error))
                .scopeRule(makePassValidationRule(this.client))
                .ownerRule(makePassValidationRule(this.client)).build();

        ClientInvalidException e = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
        assertTrue(e.getErrors().contains(error));
    }

    @Test
    @DisplayName("클라이언트 스코프가 유효 하지 않을떄 유효성 체크")
    void validationWhenClientScopeNotAllowed() {
        ValidationError error = new ValidationError("scope", "invalid scope");
        OAuth2ClientValidatePolicy policy = makeValidationPolicy().clientIdRule(makePassValidationRule(this.client))
                .secretRule(makePassValidationRule(this.client))
                .clientNameRule(makePassValidationRule(this.client))
                .grantTypeRule(makePassValidationRule(this.client))
                .scopeRule(makeErrorValidationRule(this.client, error))
                .ownerRule(makePassValidationRule(this.client)).build();

        ClientInvalidException e = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
        assertTrue(e.getErrors().contains(error));
    }

    @Test
    @DisplayName("클라이언트 소유자가 유효 하지 않을떄 유효성 체크")
    void validationWhenClientOwnerNotAllowed() {
        ValidationError error = new ValidationError("owner", "invalid owner");
        OAuth2ClientValidatePolicy policy = makeValidationPolicy().clientIdRule(makePassValidationRule(this.client))
                .secretRule(makePassValidationRule(this.client))
                .clientNameRule(makePassValidationRule(this.client))
                .grantTypeRule(makePassValidationRule(this.client))
                .scopeRule(makePassValidationRule(this.client))
                .ownerRule(makeErrorValidationRule(this.client, error)).build();

        ClientInvalidException e = assertThrows(ClientInvalidException.class, () -> client.validate(policy));
        assertTrue(e.getErrors().contains(error));
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