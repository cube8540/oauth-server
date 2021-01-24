package cube8540.oauth.authentication.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.oauth.error.InvalidClientException;
import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import cube8540.oauth.authentication.oauth.token.domain.OAuth2RefreshTokenRepository;
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
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.APPROVED_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.COMPOSE_UNIQUE_KEY;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.DIFFERENT_CLIENT;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.NEW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.NEW_REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_APPROVED_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.REFRESH_TOKEN_VALIDITY_SECONDS;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.SCOPES;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_CREATED_DATETIME;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeComposeUniqueKeyGenerator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyRefreshTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeErrorValidator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeExistsAccessToken;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makePassValidator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeRefreshToken;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeRefreshTokenRepository;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenIdGenerator;
import static cube8540.oauth.authentication.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("리플레시 토큰을 통한 토큰 부여 테스트")
class RefreshTokenGranterTest {

    @Test
    @DisplayName("요청한 리플래시 토큰이 null 일시")
    void generateAccessTokenWhenRequestRefreshTokenIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        when(request.getRefreshToken()).thenReturn(null);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("등록 되지 않은 리플래시 토큰으로 엑세스 토큰 생성")
    void generateAccessTokenByNotRegisteredRefreshToken() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeEmptyRefreshTokenRepository();
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_GRANT, error.getErrorCode());
    }

    @Test
    @DisplayName("만료된 리플래시 토큰으로 엑세스 토큰 생성")
    void generateAccessTokenByExpiredRefreshToken() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        when(refreshToken.isExpired()).thenReturn(true);

        assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request));
        verify(refreshTokenRepository, times(1)).delete(refreshToken);
    }

    @Test
    @DisplayName("요청 클라이언트와 리플래시 토큰의 클라이언트가 서로 다를때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestClientAndRefreshTokenClientAreDifferent() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        when(accessToken.getClient()).thenReturn(DIFFERENT_CLIENT);

        OAuth2Error error = assertThrows(InvalidClientException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_CLIENT, error.getErrorCode());
    }

    @Test
    @DisplayName("요청 스코프가 유효 하지 않을때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestScopeIsNotAllowed() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(ACCESS_TOKEN_ID);
        OAuth2RequestValidator validator = makeErrorValidator(RAW_APPROVED_SCOPES, RAW_SCOPES);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        granter.setTokenRequestValidator(validator);

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> granter.createAccessToken(clientDetails, request)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_SCOPE, error.getErrorCode());
    }

    @Test
    @DisplayName("리플래시 토큰 아이디 생성자가 설정 되어 있지 않을때 액세스 토큰 생성")
    void generateAccessTokenWhenRefreshTokenIdGeneratorNotSet() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2RequestValidator validator = makePassValidator(RAW_APPROVED_SCOPES, RAW_SCOPES);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken newAccessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(NEW_ACCESS_TOKEN_ID, newAccessToken.getRefreshToken().getTokenId());
        assertAccessToken(refreshToken, refreshTokenRepository, newAccessToken);
    }

    @Test
    @DisplayName("리플래시 토큰 아이디 생성자가 설정 되어 있을때 엑세스 토큰 생성")
    void generateAccessTokenWhenRefreshTokenIdGeneratorSet() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2TokenIdGenerator refreshTokenIdGenerator = makeTokenIdGenerator(NEW_REFRESH_TOKEN_ID);
        OAuth2RequestValidator validator = makePassValidator(RAW_APPROVED_SCOPES, RAW_SCOPES);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
        granter.setTokenRequestValidator(validator);
        granter.setRefreshTokenIdGenerator(refreshTokenIdGenerator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken newAccessToken = granter.createAccessToken(clientDetails, request);
        assertEquals(NEW_REFRESH_TOKEN_ID, newAccessToken.getRefreshToken().getTokenId());
        assertAccessToken(refreshToken, refreshTokenRepository, newAccessToken);
    }

    @Test
    @DisplayName("요청한 스코프가 null 일때 액세스 토큰 생성")
    void generateNewAccessTokenWhenRequestScopesIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2RequestValidator validator = makePassValidator(RAW_APPROVED_SCOPES, null);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        when(request.getScopes()).thenReturn(null);

        OAuth2AuthorizedAccessToken newAccessToken = granter.createAccessToken(clientDetails, request);
        assertAccessToken(refreshToken, refreshTokenRepository, newAccessToken);
        assertEquals(APPROVED_SCOPES, newAccessToken.getScopes());
    }

    @Test
    @DisplayName("요청한 스코프가 비어 있을때 액세스 토큰 생성")
    void generateNewAccessTokenWhenRequestScopesIsEmpty() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2RequestValidator validator = makePassValidator(RAW_APPROVED_SCOPES, Collections.emptySet());
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);
        when(request.getScopes()).thenReturn(Collections.emptySet());

        OAuth2AuthorizedAccessToken newAccessToken = granter.createAccessToken(clientDetails, request);
        assertAccessToken(refreshToken, refreshTokenRepository, newAccessToken);
        assertEquals(APPROVED_SCOPES, newAccessToken.getScopes());
    }

    @Test
    @DisplayName("요청 스코프가 유효할 때 액세스 토큰 생성")
    void generateAccessTokenWhenRequestScopesIsAllowed() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = makeComposeUniqueKeyGenerator();
        OAuth2RequestValidator validator = makePassValidator(RAW_APPROVED_SCOPES, RAW_SCOPES);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        Clock clock = Clock.fixed(TOKEN_CREATED_DATETIME.toInstant(AuthenticationApplication.DEFAULT_ZONE_OFFSET), AuthenticationApplication.DEFAULT_TIME_ZONE.toZoneId());
        AbstractOAuth2TokenGranter.setClock(clock);
        granter.setTokenRequestValidator(validator);
        granter.setComposeUniqueKeyGenerator(composeUniqueKeyGenerator);

        OAuth2AuthorizedAccessToken newAccessToken = granter.createAccessToken(clientDetails, request);
        assertAccessToken(refreshToken, refreshTokenRepository, newAccessToken);
        assertEquals(SCOPES, newAccessToken.getScopes());
    }

    @Test
    @DisplayName("기존 토큰 반환 여부는 반드시 false 가 반환 되어야 한다.")
    void isReturnsExistingTokenMethodShouldReturnsFalse() {
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken(APPROVED_SCOPES);
        OAuth2AuthorizedRefreshToken refreshToken = makeRefreshToken(accessToken);
        OAuth2AccessTokenRepository accessTokenRepository = makeEmptyAccessTokenRepository();
        OAuth2RefreshTokenRepository refreshTokenRepository = makeRefreshTokenRepository(REFRESH_TOKEN_ID, refreshToken);
        OAuth2TokenIdGenerator generator = makeTokenIdGenerator(NEW_ACCESS_TOKEN_ID);
        RefreshTokenGranter granter = new RefreshTokenGranter(accessTokenRepository, refreshTokenRepository, generator);

        assertFalse(granter.isReturnsExistsToken(makeExistsAccessToken(), makeAccessToken()));
    }

    private void assertAccessToken(OAuth2AuthorizedRefreshToken refreshToken, OAuth2RefreshTokenRepository refreshTokenRepository, OAuth2AuthorizedAccessToken newAccessToken) {
        assertEquals(NEW_ACCESS_TOKEN_ID, newAccessToken.getTokenId());
        assertEquals(CLIENT_ID, newAccessToken.getClient());
        assertEquals(USERNAME, newAccessToken.getUsername());
        assertEquals(AuthorizationGrantType.AUTHORIZATION_CODE, newAccessToken.getTokenGrantType());
        assertEquals(TOKEN_CREATED_DATETIME, newAccessToken.getIssuedAt());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(ACCESS_TOKEN_VALIDITY_SECONDS), newAccessToken.getExpiration());
        assertEquals(TOKEN_CREATED_DATETIME.plusSeconds(REFRESH_TOKEN_VALIDITY_SECONDS), newAccessToken.getRefreshToken().getExpiration());
        assertEquals(COMPOSE_UNIQUE_KEY, newAccessToken.getComposeUniqueKey());
        verify(refreshTokenRepository, times(1)).delete(refreshToken);
    }
}