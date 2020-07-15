package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_ACCESS_TOKEN_ID;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_CLIENT_ID;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_SCOPES;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_USERNAME;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.makeAccessToken;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.makeAccessTokenDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.makeEmptyAccessTokenDetailsService;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.makeUserDetails;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@DisplayName("기본 액세스 토큰 교환 클래스 테스트")
class DefaultAccessTokenIntrospectorTest {

    @Test
    @DisplayName("토큰을 찾을 수 없을떄")
    void whenNotFoundAccessToken() {
        OAuth2AccessTokenDetailsService service = makeEmptyAccessTokenDetailsService();
        DefaultAccessTokenIntrospector introspector = new DefaultAccessTokenIntrospector(service);

        assertThrows(OAuth2IntrospectionException.class, () -> introspector.introspect(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("토큰이 만료 되었을 떄")
    void whenTokenIsExpiration() {
        OAuth2AccessTokenDetails accessToken = makeAccessToken();
        OAuth2AccessTokenDetailsService service = makeAccessTokenDetailsService(accessToken, makeUserDetails());
        DefaultAccessTokenIntrospector introspector = new DefaultAccessTokenIntrospector(service);

        when(accessToken.isExpired()).thenReturn(true);

        assertThrows(OAuth2IntrospectionException.class, () -> introspector.introspect(RAW_ACCESS_TOKEN_ID));
    }

    @Test
    @DisplayName("토큰의 소유자가 null 일 때")
    void whenTokenOwnerPropertyIsNull() {
        OAuth2AccessTokenDetails accessToken = makeAccessToken();
        OAuth2AccessTokenDetailsService service = makeAccessTokenDetailsService(accessToken, makeUserDetails());
        DefaultAccessTokenIntrospector introspector = new DefaultAccessTokenIntrospector(service);

        when(accessToken.getUsername()).thenReturn(null);

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(RAW_ACCESS_TOKEN_ID);
        assertEquals(RAW_CLIENT_ID, principal.getAttribute(OAuth2IntrospectionClaimNames.CLIENT_ID));
        assertEquals(extractAuthorities(), principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE));
        assertTokenAuthorities(principal);
        assertTokenAdditionalInfo(principal);
        assertNull(principal.getName());
    }

    @Test
    @DisplayName("토큰의 소유자가 null 이 아닐떄")
    void whenTokenOwnerPropertyIsNotNull() {
        OAuth2AccessTokenDetails accessToken = makeAccessToken();
        OAuth2AccessTokenDetailsService service = makeAccessTokenDetailsService(accessToken, makeUserDetails());
        DefaultAccessTokenIntrospector introspector = new DefaultAccessTokenIntrospector(service);

        when(accessToken.getUsername()).thenReturn(RAW_USERNAME);

        OAuth2AuthenticatedPrincipal principal = introspector.introspect(RAW_ACCESS_TOKEN_ID);
        assertEquals(RAW_CLIENT_ID, principal.getAttribute(OAuth2IntrospectionClaimNames.CLIENT_ID));
        assertEquals(extractAuthorities(), principal.getAttribute(OAuth2IntrospectionClaimNames.SCOPE));
        assertTokenAuthorities(principal);
        assertTokenAdditionalInfo(principal);
        assertEquals(RAW_USERNAME, principal.getName());
    }

    private void assertTokenAdditionalInfo(OAuth2AuthenticatedPrincipal principal) {
        assertEquals("TEST-1-VALUE", principal.getAttribute("TEST-1"));
        assertEquals("TEST-2-VALUE", principal.getAttribute("TEST-2"));
        assertEquals("TEST-3-VALUE", principal.getAttribute("TEST-3"));
    }

    private void assertTokenAuthorities(OAuth2AuthenticatedPrincipal principal) {
        List<GrantedAuthority> extract = new ArrayList<>(extractAuthorities());
        List<GrantedAuthority> actual = new ArrayList<>(principal.getAuthorities());
        assertEquals(extract, actual);
    }

    private Collection<GrantedAuthority> extractAuthorities() {
        return RAW_SCOPES.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}