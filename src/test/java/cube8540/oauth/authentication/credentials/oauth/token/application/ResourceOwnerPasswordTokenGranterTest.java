package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.UserDeniedAuthorizationException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.AUTHENTICATION_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.COMPOSE_UNIQUE_KEY;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.PASSWORD;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_AUTHENTICATION_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthentication;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAuthenticationManager;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeBadCredentials;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeBadStatus;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeComposeUniqueKeyGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeErrorValidator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makePassValidator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenIdGenerator;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@DisplayName("자원 소유자의 패스워드를 통한 토큰 부여 테스트")
class ResourceOwnerPasswordTokenGranterTest {

    @Test
    @DisplayName("요청 객체에서 유저 아이디가 null일 떄 엑세스 토큰 생성")
    void generateAccessTokenWhenUsernameOfRequestIsNull() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest tokenRequest = makeTokenRequest();
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(makeTokenIdGenerator(ACCESS_TOKEN_ID), repository, makeAuthenticationManager());

        when(tokenRequest.getUsername()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, tokenRequest)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("요청 객체에서 유저 패스워드가 null일 떄 엑세스 토큰 생성")
    void generateAccessTokenWhenPasswordOfRequestIsNull() {
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest tokenRequest = makeTokenRequest();
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(makeTokenIdGenerator(ACCESS_TOKEN_ID), repository, makeAuthenticationManager());

        when(tokenRequest.getPassword()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, tokenRequest)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("요청 받은 스코프가 유효 하지 않을때 엑세스 토큰 생성")
    void generateAccessTokenWhenRequestScopeIsNotAllowed() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makeErrorValidator(clientDetails, RAW_SCOPES);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        AuthenticationManager manager = makeAuthenticationManager();
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        granter.setTokenRequestValidator(validator);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("계정 인증에 실패 했을때 엑세스 토큰 생성")
    void generateAccessTokenWhenAuthenticationFailure() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        AuthenticationManager manager = makeBadCredentials(usernamePasswordToken);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        assertThrows(UserDeniedAuthorizationException.class, () -> granter.createAccessToken(clientDetails, request));
    }

    @Test
    @DisplayName("계정의 상태가 유효 하지 않을떄 엑세스 토큰 생성")
    void generateAccessTokenWhenAccountNotAllowed() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        AuthenticationManager manager = makeBadStatus(usernamePasswordToken);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        assertThrows(UserDeniedAuthorizationException.class, () -> granter.createAccessToken(clientDetails, request));
    }

    @Test
    @DisplayName("리플래시 토큰 아이디 생성자가 설정 되어 있지 않을때 엑세스 토큰 생성")
    void generateAccessTokenWhenRefreshTokenIdGeneratorIsNotSet() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        Authentication authentication = makeAuthentication(RAW_AUTHENTICATION_USERNAME);
        AuthenticationManager manager = makeAuthenticationManager(usernamePasswordToken, authentication);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        configNotExpirationClock();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("리플래시 토큰 아이디 생성자가 설정 되어 있을때 엑세스 토큰 생성")
    void generateAccessTokenWhenRefreshTokenIdGeneratorIsSet() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2TokenIdGenerator refreshTokenIdGenerator = makeTokenIdGenerator(REFRESH_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        Authentication authentication = makeAuthentication(RAW_AUTHENTICATION_USERNAME);
        AuthenticationManager manager = makeAuthenticationManager(usernamePasswordToken, authentication);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        configNotExpirationClock();
        granter.setTokenRequestValidator(validator);
        granter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("요청 스코프가 null 일때 엑세스 토큰 생성")
    void generateAccessTokenWhenRequestScopeIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, null);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        Authentication authentication = makeAuthentication(RAW_AUTHENTICATION_USERNAME);
        AuthenticationManager manager = makeAuthenticationManager(usernamePasswordToken, authentication);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        configNotExpirationClock();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        when(request.getScopes()).thenReturn(null);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(CLIENT_SCOPES, accessToken.getScopes());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("요청 스코프가 비어 있을때 엑세스 토큰 생성")
    void generateAccessTokenWhenRequestScopeIsEmpty() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, Collections.emptySet());
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        Authentication authentication = makeAuthentication(RAW_AUTHENTICATION_USERNAME);
        AuthenticationManager manager = makeAuthenticationManager(usernamePasswordToken, authentication);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        configNotExpirationClock();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        when(request.getScopes()).thenReturn(Collections.emptySet());

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(CLIENT_SCOPES, accessToken.getScopes());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("요청 스코프가 유효할 때 엑세스 토큰 생성")
    void generateAccessTokenWhenRequestScopeIsAllowed() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        UsernamePasswordAuthenticationToken usernamePasswordToken = new UsernamePasswordAuthenticationToken(RAW_USERNAME, PASSWORD);
        Authentication authentication = makeAuthentication(RAW_AUTHENTICATION_USERNAME);
        AuthenticationManager manager = makeAuthenticationManager(usernamePasswordToken, authentication);
        ResourceOwnerPasswordTokenGranter granter = new ResourceOwnerPasswordTokenGranter(generator, repository, manager);

        configNotExpirationClock();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(SCOPES, accessToken.getScopes());
        assertAccessToken(accessToken);
    }

    private void configNotExpirationClock() {
        Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
    }

    private void assertAccessToken(OAuth2AuthorizedAccessToken accessToken) {
        assertEquals(ACCESS_TOKEN_ID, accessToken.getTokenId());
        assertEquals(CLIENT_ID, accessToken.getClient());
        assertEquals(AUTHENTICATION_USERNAME, accessToken.getUsername());
        assertEquals(AuthorizationGrantType.PASSWORD, accessToken.getTokenGrantType());
        assertEquals(TOKEN_CREATED_DATETIME, accessToken.getIssuedAt());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), accessToken.getRefreshToken().getExpiration());
        assertEquals(COMPOSE_UNIQUE_KEY, accessToken.getComposeUniqueKey());
    }
}
