package cube8540.oauth.authentication.credentials.oauth.token.domain;

import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.LocalDateTime;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2AccessTokenTestHelper {

    static final String RAW_ACCESS_TOKEN_ID = "ACCESS-TOKEN-ID";
    static final OAuth2TokenId ACCESS_TOKEN_ID = new OAuth2TokenId(RAW_ACCESS_TOKEN_ID);

    static final String RAW_REFRESH_TOKEN_ID = "REFRESH-TOKEN-ID";
    static final OAuth2TokenId REFRESH_TOKEN_ID = new OAuth2TokenId(RAW_REFRESH_TOKEN_ID);

    static final String RAW_USERNAME = "username";
    static final PrincipalUsername USERNAME = new PrincipalUsername(RAW_USERNAME);

    static final String RAW_CLIENT_ID = "CLIENT-ID";
    static final OAuth2ClientId CLIENT_ID = new OAuth2ClientId(RAW_CLIENT_ID);

    static final AuthorizationGrantType GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

    static final LocalDateTime EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 29, 22, 51);
    static final LocalDateTime REFRESH_EXPIRATION_DATETIME = LocalDateTime.of(2020, 1, 29, 11, 9);

    static final String RAW_COMPOSE_UNIQUE_KEY = "COMPOSE_UNIQUE_KEY";
    static final OAuth2ComposeUniqueKey COMPOSE_UNIQUE_KEY = new OAuth2ComposeUniqueKey(RAW_COMPOSE_UNIQUE_KEY);

    static OAuth2ComposeUniqueKeyGenerator makeComposeUniqueKeyGenerator(OAuth2AuthorizedAccessToken accessToken) {
        OAuth2ComposeUniqueKeyGenerator generator = mock(OAuth2ComposeUniqueKeyGenerator.class);

        when(generator.generateKey(accessToken)).thenReturn(COMPOSE_UNIQUE_KEY);

        return generator;
    }

    static OAuth2TokenIdGenerator makeAccessTokenIdGenerator() {
        OAuth2TokenIdGenerator generator = mock(OAuth2TokenIdGenerator.class);
        when(generator.generateTokenValue()).thenReturn(ACCESS_TOKEN_ID);
        return generator;
    }

    static OAuth2TokenIdGenerator makeRefreshTokenIdGenerator() {
        OAuth2TokenIdGenerator generator = mock(OAuth2TokenIdGenerator.class);
        when(generator.generateTokenValue()).thenReturn(REFRESH_TOKEN_ID);
        return generator;
    }


    static OAuth2AuthorizedAccessToken makeAccessToken() {
        return mock(OAuth2AuthorizedAccessToken.class);
    }
}
