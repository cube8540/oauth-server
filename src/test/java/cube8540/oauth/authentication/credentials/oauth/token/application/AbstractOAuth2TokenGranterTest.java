package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.ADDITIONAL_INFO;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.EXPIRATION_DATETIME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.EXPIRATION_IN;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_EXISTS_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.TOKEN_TYPE;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeEmptyAccessTokenRepository;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeExistsAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeExpiredExistsAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenEnhancer;
import static cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2TokenApplicationTestHelper.makeTokenRequest;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("OAuth2 토큰 부여 추상 클래스 테스트")
class AbstractOAuth2TokenGranterTest {

    @Test
    @DisplayName("엑세스 토큰의 소유자가 요청한 클라이언트와 같은 방식으로 이미 인증을 받은 상태일 떄 새 엑세스 토큰을 부여")
    void accessTokenGrantsNewTokenWhenAlreadyAuthenticatedByRequestedClientAndSameGrantType() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenEnhancer enhancer = makeTokenEnhancer();
        OAuth2AuthorizedAccessToken existsAccessToken = makeExistsAccessToken();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(CLIENT_ID, USERNAME, existsAccessToken);
        AbstractOAuth2TokenGranter granter = mock(AbstractOAuth2TokenGranter.class, CALLS_REAL_METHODS);

        granter.setTokenEnhancer(enhancer);
        granter.setTokenRepository(repository);
        when(granter.createAccessToken(clientDetails, request)).thenReturn(accessToken);

        OAuth2AccessTokenDetails token = granter.grant(clientDetails, request);
        verify(enhancer, never()).enhance(accessToken);
        verify(repository, never()).save(accessToken);
        verify(repository, never()).delete(existsAccessToken);
        assertExistsAccessToken(token);
    }

    @Test
    @DisplayName("엑세스 토큰의 소유자가 요청한 클라이언트와 다른 방식으로 이미 인증을 받은 상태일 떄 새 엑세스 토큰을 부여")
    void accessTokenGrantsNewTokenWhenAlreadyAuthenticatedByRequestedClientAndDifferentGrantType() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenEnhancer enhancer = makeTokenEnhancer();
        OAuth2AuthorizedAccessToken existsAccessToken = makeExistsAccessToken(AuthorizationGrantType.PASSWORD);
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(CLIENT_ID, USERNAME, existsAccessToken);
        AbstractOAuth2TokenGranter granter = mock(AbstractOAuth2TokenGranter.class, CALLS_REAL_METHODS);

        granter.setTokenEnhancer(enhancer);
        granter.setTokenRepository(repository);
        when(granter.createAccessToken(clientDetails, request)).thenReturn(accessToken);

        OAuth2AccessTokenDetails token = granter.grant(clientDetails, request);
        InOrder inOrder = Mockito.inOrder(repository, enhancer);
        inOrder.verify(repository, times(1)).delete(existsAccessToken);
        inOrder.verify(enhancer, times(1)).enhance(accessToken);
        inOrder.verify(repository, times(1)).save(accessToken);
        assertAccessToken(token);
    }

    @Test
    @DisplayName("이미 인증 받은 엑세스 토큰이 만료 되었을시")
    void accessTokenGrantsNewTokenWhenAlreadyAuthenticatedAccessTokenIsExpired() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenEnhancer enhancer = makeTokenEnhancer();
        OAuth2AuthorizedAccessToken existsAccessToken = makeExpiredExistsAccessToken();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeAccessTokenRepository(CLIENT_ID, USERNAME, existsAccessToken);
        AbstractOAuth2TokenGranter granter = mock(AbstractOAuth2TokenGranter.class, CALLS_REAL_METHODS);

        granter.setTokenEnhancer(enhancer);
        granter.setTokenRepository(repository);
        when(granter.createAccessToken(clientDetails, request)).thenReturn(accessToken);

        OAuth2AccessTokenDetails token = granter.grant(clientDetails, request);
        InOrder inOrder = Mockito.inOrder(repository, enhancer);
        inOrder.verify(repository, times(1)).delete(existsAccessToken);
        inOrder.verify(enhancer, times(1)).enhance(accessToken);
        inOrder.verify(repository, times(1)).save(accessToken);
        assertAccessToken(token);
    }

    @Test
    @DisplayName("엑세스 토큰 부여")
    void accessTokenGrants() {
        OAuth2TokenRequest request = makeTokenRequest();
        OAuth2ClientDetails clientDetails = makeClientDetails();
        OAuth2TokenEnhancer enhancer = makeTokenEnhancer();
        OAuth2AuthorizedAccessToken accessToken = makeAccessToken();
        OAuth2AccessTokenRepository repository = makeEmptyAccessTokenRepository();
        AbstractOAuth2TokenGranter granter = mock(AbstractOAuth2TokenGranter.class, CALLS_REAL_METHODS);

        granter.setTokenEnhancer(enhancer);
        granter.setTokenRepository(repository);
        when(granter.createAccessToken(clientDetails, request)).thenReturn(accessToken);

        OAuth2AccessTokenDetails token = granter.grant(clientDetails, request);
        InOrder inOrder = Mockito.inOrder(repository, enhancer);
        inOrder.verify(enhancer, times(1)).enhance(accessToken);
        inOrder.verify(repository, times(1)).save(accessToken);
        assertAccessToken(token);
    }

    private void assertAccessToken(OAuth2AccessTokenDetails token) {
        assertEquals(RAW_ACCESS_TOKEN_ID, token.getTokenValue());
        assertEquals(EXPIRATION_DATETIME, token.getExpiration());
        assertEquals(EXPIRATION_IN, token.getExpiresIn());
        assertEquals(RAW_CLIENT_ID, token.getClientId());
        assertEquals(RAW_SCOPES, token.getScopes());
        assertEquals(RAW_USERNAME, token.getUsername());
        assertEquals(ADDITIONAL_INFO, token.getAdditionalInformation());
        assertEquals(TOKEN_TYPE, token.getTokenType());
    }

    private void assertExistsAccessToken(OAuth2AccessTokenDetails token) {
        assertEquals(RAW_EXISTS_ACCESS_TOKEN_ID, token.getTokenValue());
        assertEquals(EXPIRATION_DATETIME, token.getExpiration());
        assertEquals(EXPIRATION_IN, token.getExpiresIn());
        assertEquals(RAW_CLIENT_ID, token.getClientId());
        assertEquals(RAW_SCOPES, token.getScopes());
        assertEquals(RAW_USERNAME, token.getUsername());
        assertEquals(ADDITIONAL_INFO, token.getAdditionalInformation());
        assertEquals(TOKEN_TYPE, token.getTokenType());
    }
}
