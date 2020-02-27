package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2AccessTokenTestHelper {

    static final String RAW_ACCESS_TOKEN_ID = "ACCESS-TOKEN-ID";
    static final OAuth2TokenId ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_ACCESS_TOKEN_ID);

    static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    static final String RAW_USERNAME = "email@email.com";
    static final UserEmail USERNAME = new UserEmail(RAW_USERNAME);

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 51);
    static final LocalDateTime REFRESH_EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 29, 11, 9);

    static final Set<String> RAW_SCOPES_ID = new HashSet<>(Arrays.asList("SCOPE-1", "SCOPE-2", "SCOPE-3"));
    static final Set<OAuth2ScopeId> SCOPES_ID = RAW_SCOPES_ID.stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());

    static OAuth2TokenIdGenerator configAccessTokenIdGenerator() {
        OAuth2TokenIdGenerator generator = mock(OAuth2TokenIdGenerator.class);
        when(generator.generateTokenValue()).thenReturn(ACCESS_TOKEN_ID);
        return generator;
    }

    static OAuth2TokenIdGenerator configRefreshTokenIdGenerator() {
        OAuth2TokenIdGenerator generator = mock(OAuth2TokenIdGenerator.class);
        when(generator.generateTokenValue()).thenReturn(REFRESH_TOKEN_ID);
        return generator;
    }


    static OAuth2AuthorizedAccessToken mockAccessToken() {
        return mock(OAuth2AuthorizedAccessToken.class);
    }
}
