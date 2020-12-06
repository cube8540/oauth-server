package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetailsService;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenNotFoundException;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.PrincipalUsername;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpaqueTokenIntrospectorTestSupport {

    static final String TOKEN_TYPE = "Bearer";

    static final String RAW_ACCESS_TOKEN_ID = "ACCESS-TOKEN-ID";
    static final OAuth2TokenId ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_ACCESS_TOKEN_ID);

    static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    static final String RAW_USERNAME = "username";
    static final PrincipalUsername USERNAME = new PrincipalUsername(RAW_USERNAME);

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);
    static final String RAW_DIFFERENT_CLIENT_ID = "DIFFERENT_CLIENT_ID";
    static final String CLIENT_SECRET = "CLIENT-SECRET";

    static final Set<String> RAW_SCOPES = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    static final Set<AuthorityCode> SCOPES = RAW_SCOPES.stream().map(AuthorityCode::new).collect(Collectors.toSet());

    static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 24, 21, 24, 0);

    static final Map<String, String> ADDITIONAL_INFO = new HashMap<>();

    static {
        ADDITIONAL_INFO.put("TEST-1", "TEST-1-VALUE");
        ADDITIONAL_INFO.put("TEST-2", "TEST-2-VALUE");
        ADDITIONAL_INFO.put("TEST-3", "TEST-3-VALUE");
    }

    static OAuth2AccessTokenDetails makeAccessToken() {
        OAuth2AccessTokenDetails token = mock(OAuth2AccessTokenDetails.class);

        when(token.getTokenValue()).thenReturn(RAW_ACCESS_TOKEN_ID);
        when(token.getClientId()).thenReturn(RAW_CLIENT_ID);
        when(token.getUsername()).thenReturn(RAW_USERNAME);
        when(token.getScopes()).thenReturn(RAW_SCOPES);
        when(token.getExpiration()).thenReturn(EXPIRATION_DATETIME);
        when(token.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
        when(token.isExpired()).thenReturn(false);

        return token;
    }

    static OAuth2AccessTokenDetails makeDifferentClientAccessToken() {
        OAuth2AccessTokenDetails token = mock(OAuth2AccessTokenDetails.class);

        when(token.getTokenValue()).thenReturn(RAW_ACCESS_TOKEN_ID);
        when(token.getClientId()).thenReturn(RAW_DIFFERENT_CLIENT_ID);
        when(token.getUsername()).thenReturn(RAW_USERNAME);
        when(token.getScopes()).thenReturn(RAW_SCOPES);
        when(token.getExpiration()).thenReturn(EXPIRATION_DATETIME);
        when(token.getAdditionalInformation()).thenReturn(ADDITIONAL_INFO);
        when(token.isExpired()).thenReturn(false);

        return token;
    }

    static User makeUserDetails() {
        return mock(User.class);
    }

    static OAuth2AccessTokenDetailsService makeEmptyAccessTokenDetailsService() {
        OAuth2AccessTokenDetailsService service = mock(OAuth2AccessTokenDetailsService.class);

        when(service.readAccessToken(any())).thenThrow(new OAuth2AccessTokenNotFoundException("TEST"));
        when(service.readAccessTokenUser(any())).thenThrow(new OAuth2AccessTokenNotFoundException("TEST"));

        return service;
    }

    static OAuth2AccessTokenDetailsService makeAccessTokenDetailsService(OAuth2AccessTokenDetails accessToken, UserDetails user) {
        OAuth2AccessTokenDetailsService service = mock(OAuth2AccessTokenDetailsService.class);

        when(service.readAccessToken(RAW_ACCESS_TOKEN_ID)).thenReturn(accessToken);
        when(service.readAccessTokenUser(RAW_ACCESS_TOKEN_ID)).thenReturn(user);

        return service;
    }

    static Authentication makeRequestAuthentication(String clientId, String clientSecret) {
        return new ClientCredentialsToken(clientId, clientSecret);
    }

    static AuthenticationProvider makeAuthenticationProvider(Authentication authentication) {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        Authentication auth = mock(Authentication.class);

        when(provider.authenticate(authentication)).thenReturn(auth);
        when(auth.getName()).thenReturn(authentication.getName());

        return provider;
    }

    static AuthenticationProvider makeExceptionAuthenticationProvider(Authentication authentication) {
        AuthenticationProvider provider = mock(AuthenticationProvider.class);
        Authentication auth = mock(Authentication.class);

        when(provider.authenticate(authentication)).thenThrow(new RuntimeException());
        when(auth.getName()).thenReturn(authentication.getName());

        return provider;
    }
}
