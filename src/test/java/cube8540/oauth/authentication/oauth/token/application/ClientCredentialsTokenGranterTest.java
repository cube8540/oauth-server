package cube8540.oauth.authentication.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2TokenIdGenerator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.time.Clock;
import java.util.Collections;

import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.ACCESS_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.COMPOSE_UNIQUE_KEY;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeComposeUniqueKeyGenerator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeErrorValidator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makePassValidator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenIdGenerator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@DisplayName("클라이언트 인증을 통한 토큰 부여 테스트")
class ClientCredentialsTokenGranterTest {

    @Test
    @DisplayName("요청 받은 스코프가 유효 하지 않을때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestScopeIsNotAllowed() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makeErrorValidator(clientDetails, RAW_SCOPES);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        granter.setTokenRequestValidator(validator);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("요청 받은 스코프가 null 일때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestScopesIsNull() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, null);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        configNotExpirationTime();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        when(request.getScopes()).thenReturn(null);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(CLIENT_SCOPES, accessToken.getScopes());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("요청 받은 스코프가 비어 있을때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestScopesIsEmpty() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, Collections.emptySet());
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        configNotExpirationTime();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        when(request.getScopes()).thenReturn(Collections.emptySet());

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(CLIENT_SCOPES, accessToken.getScopes());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("요청 받은 스코프가 비어 있지 않을때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestScopesIsNotEmpty() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        configNotExpirationTime();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(SCOPES, accessToken.getScopes());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("리플래시 토큰 사용 여부가 false 로 설정 되어 있을떄")
    void whetherOrNotToUseRefreshTokenIsSetToFalse() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        configNotExpirationTime();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        granter.setAllowedRefreshToken(false);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertNull(accessToken.getRefreshToken());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("리플래시 토큰 사용 여부가 true로 설정 되어 있으며 리플래시 토큰 아이디 생성자가 설정 되어 있지 않을시")
    void whetherOrNotToUseRefreshTokenIsSetToTrueAndRefreshTokenIdGeneratorIsNotSet() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        configNotExpirationTime();
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        granter.setAllowedRefreshToken(true);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(ACCESS_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
        assertAccessToken(accessToken);
    }

    @Test
    @DisplayName("리플래시 토큰 사용 여부가 true로 설정 되어 있으며 리플래시 토큰 아이디 생성자가 설정 되어 있을시")
    void whetherOrNotToUseRefreshTokenIsSetToTrueAndRefreshTokenIdGeneratorIsSet() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2RequestValidator validator = makePassValidator(clientDetails, RAW_SCOPES);
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2TokenIdGenerator refreshTokenIdGenerator = makeTokenIdGenerator(REFRESH_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        ClientCredentialsTokenGranter granter = new ClientCredentialsTokenGranter(generator, repository);

        configNotExpirationTime();
        granter.setTokenRequestValidator(validator);
        granter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        granter.setAllowedRefreshToken(true);

        OAuth2AuthorizedAccessToken accessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(REFRESH_TOKEN_ID, accessToken.getRefreshToken().getTokenId());
        assertAccessToken(accessToken);
    }

    private static void configNotExpirationTime() {
        Clock clock = Clock.fixed(OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
    }

    private void assertAccessToken(OAuth2AuthorizedAccessToken accessToken) {
        assertEquals(ACCESS_TOKEN_ID, accessToken.getTokenId());
        assertNull(accessToken.getUsername());
        assertEquals(CLIENT_ID, accessToken.getClient());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, accessToken.getTokenGrantType());
        assertEquals(TOKEN_CREATED_DATETIME, accessToken.getIssuedAt());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), accessToken.getExpiration());
        assertEquals(COMPOSE_UNIQUE_KEY, accessToken.getComposeUniqueKey());
    }
}