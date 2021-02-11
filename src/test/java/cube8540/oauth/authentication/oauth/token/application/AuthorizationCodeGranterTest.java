package cube8540.oauth.authentication.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;

import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.APPROVED_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.CODE_VERIFIER;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.COMPOSE_UNIQUE_KEY;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_APPROVED_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_AUTHORIZATION_CODE;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.STATE;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthorizationCode;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeCodeConsumer;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeComposeUniqueKeyGenerator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyCodeConsumer;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeErrorValidator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makePassValidator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenIdGenerator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("인증 코드를 통한 토큰 부여 테스트")
class AuthorizationCodeGranterTest {

    @Test
    @DisplayName("요청한 인가 코드가 null 일때")
    void generateAccessTokenWhenRequestAuthorizationCodeIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCode authorizationCode = makeAuthorizationCode();
        OAuth2AuthorizationCodeConsumer consumer = makeCodeConsumer(RAW_AUTHORIZATION_CODE, authorizationCode);
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        when(request.getCode()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("인가 코드를 찾을 수 없을떄 엑세스 토큰 생성")
    void generateAccessTokenWhenAuthorizationCodeNotFound() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCodeConsumer consumer = makeEmptyCodeConsumer();
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("인가 코드에 저장된 스코프가 유효 하지 않을때 엑세스 토큰 생성")
    void generateAccessTokenWhenScopeOfAuthorizationCodeIsNotAllowed() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCode authorizationCode = makeAuthorizationCode();
        OAuth2AuthorizationCodeConsumer consumer = makeCodeConsumer(RAW_AUTHORIZATION_CODE, authorizationCode);
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        OAuth2RequestValidator validator = makeErrorValidator(clientDetails, RAW_APPROVED_SCOPES);
        granter.setTokenRequestValidator(validator);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("인가 코드에 저장된 스코프가 null 일떄 엑세스 토큰 생성")
    void generateAccessTokenWhenScopeOfAuthorizationCodeIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCode authorizationCode = makeAuthorizationCode();
        OAuth2AuthorizationCodeConsumer consumer = makeCodeConsumer(RAW_AUTHORIZATION_CODE, authorizationCode);
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        OAuth2RequestValidator validator = makePassValidator(clientDetails, null);
        granter.setTokenRequestValidator(validator);
        when(authorizationCode.getApprovedScopes()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("인가 코드에 저장된 스코프가 비어 있을떄 엑세스 토큰 생성")
    void generateAccessTokenWhenScopeOfAuthorizationCodeIsEmpty() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCode authorizationCode = makeAuthorizationCode();
        OAuth2AuthorizationCodeConsumer consumer = makeCodeConsumer(RAW_AUTHORIZATION_CODE, authorizationCode);
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        OAuth2RequestValidator validator = makePassValidator(clientDetails, Collections.emptySet());
        granter.setTokenRequestValidator(validator);
        when(authorizationCode.getApprovedScopes()).thenReturn(Collections.emptySet());

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("리플래시 토큰 아이디 생성자가 설정 되어 있지 않을때 엑세스 토큰 생성")
    void generateAccessTokenWhenRefreshTokenIdGeneratorNotSet() {
        ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCode authorizationCode = makeAuthorizationCode();
        OAuth2AuthorizationCodeConsumer consumer = makeCodeConsumer(RAW_AUTHORIZATION_CODE, authorizationCode);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        configNotExpirationClock();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_APPROVED_SCOPES);
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        verify(authorizationCode, times(1)).validateWithAuthorizationRequest(requestCaptor.capture());
        assertEquals(REDIRECT_URI, requestCaptor.getValue().getRedirectUri());
        assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().getClientId());
        assertEquals(STATE, requestCaptor.getValue().getState());
        assertEquals(ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
        assertEquals(CODE_VERIFIER, requestCaptor.getValue().getCodeVerifier());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("리플래시 토큰 아이디 생성자가 설정 되어 있을떄 엑세스 토큰 생성")
    void generateAccessTokenWhenRefreshTokenIdGeneratorSet() {
        ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2AuthorizationCode authorizationCode = makeAuthorizationCode();
        OAuth2AuthorizationCodeConsumer consumer = makeCodeConsumer(RAW_AUTHORIZATION_CODE, authorizationCode);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        AuthorizationCodeTokenGranter granter = new AuthorizationCodeTokenGranter(generator, repository, consumer);

        configNotExpirationClock();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_APPROVED_SCOPES);
        granter.setTokenRequestValidator(validator);
        granter.setRefreshTokenIdGenerator(makeTokenIdGenerator(REFRESH_TOKEN_ID));
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        verify(authorizationCode, times(1)).validateWithAuthorizationRequest(requestCaptor.capture());
        assertEquals(REDIRECT_URI, requestCaptor.getValue().getRedirectUri());
        assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().getClientId());
        assertEquals(STATE, requestCaptor.getValue().getState());
        assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
        assertEquals(CODE_VERIFIER, requestCaptor.getValue().getCodeVerifier());
        assertAccessToken(accessToken);

    }

    private static void configNotExpirationClock() {
        Clock clock = Clock.fixed(OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
    }

    private void assertAccessToken(OAuth2AuthorizedAccessToken accessToken) {
        assertEquals(ACCESS_TOKEN_ID, accessToken.getTokenId());
        assertEquals(CLIENT_ID, accessToken.getClient());
        assertEquals(USERNAME, accessToken.getUsername());
        assertEquals(APPROVED_SCOPES, accessToken.getScopes());
        assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, accessToken.getTokenGrantType());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
        assertEquals(TOKEN_CREATED_DATETIME, accessToken.getIssuedAt());
        assertEquals(COMPOSE_UNIQUE_KEY, accessToken.getComposeUniqueKey());
    }
}