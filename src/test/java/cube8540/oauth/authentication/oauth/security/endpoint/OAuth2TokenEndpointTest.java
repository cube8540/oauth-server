package cube8540.oauth.authentication.oauth.security.endpoint;

import cube8540.oauth.authentication.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRevoker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.security.Principal;
import java.util.Map;

import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.GRANT_TYPE;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_CODE;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_PASSWORD;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_SCOPES;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_TOKEN_ID;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.REDIRECT_URI;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeAccessTokenDetails;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeClientCredentialsToken;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeNotClientCredentialsTokenPrincipal;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeRequestMap;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeRequestMapGrantTypeImplicit;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeRequestMapGrantTypeNull;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeRevokeService;
import static cube8540.oauth.authentication.oauth.security.endpoint.TokenEndpointTestHelper.makeTokenGrantService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@DisplayName("토큰 엔드 포인트 테스트")
class OAuth2TokenEndpointTest {

    @Test
    @DisplayName("요청한 부여 타입이 null 일때 토큰 부여")
    void grantTokenRequestGrantTypeIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Principal principal = makeClientCredentialsToken(clientDetails);
        OAuth2AccessTokenDetails token = makeAccessTokenDetails();
        Map<String, String> requestMap = makeRequestMapGrantTypeNull();
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(makeTokenGrantService(token), makeRevokeService(token));

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.grantNewAccessToken(principal, requestMap)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("요청한 부여 타입이 implicit 일때 토큰 부여")
    void grantTokenRequestGrantTypeImplicit() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Principal principal = makeClientCredentialsToken(clientDetails);
        OAuth2AccessTokenDetails token = makeAccessTokenDetails();
        Map<String, String> requestMap = makeRequestMapGrantTypeImplicit();
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(makeTokenGrantService(token), makeRevokeService(token));

        OAuth2Error error = assertThrows(InvalidGrantException.class, () -> endpoint.grantNewAccessToken(principal, requestMap)).getError();
        assertEquals(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, error.getErrorCode());
    }

    @Test
    @DisplayName("인증 객체의 타입이 ClientCredentialsToken 이 아닐때 토큰 부여")
    void grantTokenWhenPrincipalTypeNotClientCredentialsToken() {
        Principal principal = makeNotClientCredentialsTokenPrincipal();
        OAuth2AccessTokenDetails token = makeAccessTokenDetails();
        Map<String, String> requestMap = makeRequestMap();
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(makeTokenGrantService(token), makeRevokeService(token));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.grantNewAccessToken(principal, requestMap));
    }

    @Test
    @DisplayName("인증 상세 정보가 OAuth2ClientDetails 가 아닐때 토큰 부여")
    void grantTokenWhenPrincipalDetailsTypeNotOAuth2ClientDetails() {
        Principal principal = makeClientCredentialsToken(new Object());
        OAuth2AccessTokenDetails token = makeAccessTokenDetails();
        Map<String, String> requestMap = makeRequestMap();
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(makeTokenGrantService(token), makeRevokeService(token));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.grantNewAccessToken(principal, requestMap));
    }

    @Test
    @DisplayName("새 액세스 토큰 부여")
    void grantNewAccessToken() {
        ArgumentCaptor<OAuth2TokenRequest> requestCaptor = ArgumentCaptor.forClass(OAuth2TokenRequest.class);
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Principal principal = makeClientCredentialsToken(clientDetails);
        Map<String, String> requestMap = makeRequestMap();
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        OAuth2AccessTokenGranter granter = makeTokenGrantService(accessToken);
        OAuth2TokenRevoker revoker = makeRevokeService(accessToken);
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(granter, revoker);

        ResponseEntity<OAuth2AccessTokenDetails> result = endpoint.grantNewAccessToken(principal, requestMap);
        verify(granter, times(1)).grant(eq(clientDetails), requestCaptor.capture());
        assertEquals(new AuthorizationGrantType(GRANT_TYPE), requestCaptor.getValue().getGrantType());
        assertEquals(RAW_USERNAME, requestCaptor.getValue().getUsername());
        assertEquals(RAW_PASSWORD, requestCaptor.getValue().getPassword());
        assertEquals(RAW_CLIENT_ID, requestCaptor.getValue().getClientId());
        assertEquals(RAW_CODE, requestCaptor.getValue().getCode());
        assertEquals(REDIRECT_URI, requestCaptor.getValue().getRedirectUri());
        assertEquals(RAW_SCOPES, requestCaptor.getValue().getScopes());
        assertEquals("no-cache", result.getHeaders().getPragma());
        assertEquals(MediaType.APPLICATION_JSON, result.getHeaders().getContentType());
    }

    @Test
    @DisplayName("인증 객체의 타입이 ClientCredentialsToken이 아닐때 토큰 삭제")
    void revokeTokenWhenPrincipalTypeNotClientCredentialsToken() {
        Principal principal = makeNotClientCredentialsTokenPrincipal();
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(makeTokenGrantService(accessToken), makeRevokeService(accessToken));

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.revokeAccessToken(principal, ""));
    }

    @Test
    @DisplayName("요청 받은 토큰이 null 일때 토큰 삭제")
    void revokeTokenWhenRequestTokenIsNull() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Principal principal = makeClientCredentialsToken(clientDetails);
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(makeTokenGrantService(accessToken), makeRevokeService(accessToken));

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.revokeAccessToken(principal, null)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("토큰 삭제")
    void revokeToken() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Principal principal = makeClientCredentialsToken(clientDetails);
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        OAuth2AccessTokenGranter granter = makeTokenGrantService(accessToken);
        OAuth2TokenRevoker revoker = makeRevokeService(accessToken);
        OAuth2TokenEndpoint endpoint = new OAuth2TokenEndpoint(granter, revoker);

        endpoint.revokeAccessToken(principal, RAW_TOKEN_ID);
        verify(revoker, times(1)).revoke(RAW_TOKEN_ID);
    }
}