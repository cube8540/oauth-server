package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import java.security.Principal;
import java.util.Map;

import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.RAW_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeAccessTokenDetails;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeAccessTokenDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeAccessTokenMap;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeClientCredentialsToken;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeClientDetails;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeEmptyAccessTokenDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeIntrospectionConverter;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.TokenEndpointTestHelper.makeNotClientCredentialsTokenPrincipal;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("토큰 정보 확인 엔드 포인트 테스트")
class OAuth2TokenIntrospectionEndpointTest {

    @Test
    @DisplayName("요청 정보에 토큰이 null 일때 토큰 정보 검색")
    void searchTokenInfoWhenRequestTokenNull() {
        Principal principal = makeClientCredentialsToken(null);
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();
        OAuth2TokenIntrospectionEndpoint endpoint = new OAuth2TokenIntrospectionEndpoint(service);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.introspection(principal, null)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }

    @Test
    @DisplayName("인증 객체의 타입이 ClientCredentialsToken이 아닐때 토큰 정보 검색")
    void searchTokenInfoWhenPrincipalObjectTypeNotClientCredentialsToken() {
        Principal principal = makeNotClientCredentialsTokenPrincipal();
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();
        OAuth2TokenIntrospectionEndpoint endpoint = new OAuth2TokenIntrospectionEndpoint(service);

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.introspection(principal, RAW_TOKEN_ID));
    }

    @Test
    @DisplayName("인증의 상세 정보가 OAuth2ClientDetails가 이닐때 토큰 정보 검색")
    void searchTokenInfoWhenTokenDetailsTypeNotOauth2ClientDetails() {
        Principal principal = makeClientCredentialsToken(new Object());
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();
        OAuth2TokenIntrospectionEndpoint endpoint = new OAuth2TokenIntrospectionEndpoint(service);

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.introspection(principal, RAW_TOKEN_ID));
    }

    @Test
    @DisplayName("액세스 토큰 정보 검색")
    void searchTokenInfo() {
        OAuth2ClientDetails clientDetails = makeClientDetails();
        Principal principal = makeClientCredentialsToken(clientDetails);
        OAuth2AccessTokenDetails accessToken = makeAccessTokenDetails();
        OAuth2AccessTokenDetailsService service = makeAccessTokenDetailsService(RAW_TOKEN_ID, accessToken);
        Map<String, Object> accessTokenMap = makeAccessTokenMap();
        OAuth2AccessTokenIntrospectionConverter converter = makeIntrospectionConverter(accessToken, accessTokenMap);
        OAuth2TokenIntrospectionEndpoint endpoint = new OAuth2TokenIntrospectionEndpoint(service);

        endpoint.setConverter(converter);

        assertEquals(accessTokenMap, endpoint.introspection(principal, RAW_TOKEN_ID));
    }

    @Test
    @DisplayName("인증 객체의 타입이 ClientCredentialsToken이 아닐때 토큰 소유자 검색")
    void searchTokenOwnerWhenPrincipalTypeNotClientCredentialsToken() {
        Principal principal = makeNotClientCredentialsTokenPrincipal();
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();
        OAuth2TokenIntrospectionEndpoint endpoint = new OAuth2TokenIntrospectionEndpoint(service);

        assertThrows(InsufficientAuthenticationException.class, () -> endpoint.userInfo(principal, RAW_TOKEN_ID));
    }

    @Test
    @DisplayName("요청 받은 토큰이 null 일때 토큰 소유자 검색")
    void searchTokenOwnerWhenRequestTokenIsNull() {
        Principal principal = makeClientCredentialsToken(null);
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();
        OAuth2TokenIntrospectionEndpoint endpoint = new OAuth2TokenIntrospectionEndpoint(service);

        OAuth2Error error = assertThrows(InvalidRequestException.class, () -> endpoint.userInfo(principal, null)).getError();
        assertEquals(OAuth2ErrorCodes.INVALID_REQUEST, error.getErrorCode());
    }
}