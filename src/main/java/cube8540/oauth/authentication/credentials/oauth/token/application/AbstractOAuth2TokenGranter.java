package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.oauth.security.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class AbstractOAuth2TokenGranter implements OAuth2AccessTokenGranter {

    @Setter(AccessLevel.PROTECTED)
    private static Clock clock = AuthenticationApplication.DEFAULT_CLOCK;

    @Getter(AccessLevel.PROTECTED)
    private final OAuth2TokenIdGenerator tokenIdGenerator;

    @Setter(AccessLevel.PROTECTED)
    private OAuth2AccessTokenRepository tokenRepository;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PUBLIC)
    private OAuth2TokenIdGenerator refreshTokenIdGenerator;

    @Getter(AccessLevel.PROTECTED)
    @Setter(AccessLevel.PUBLIC)
    private OAuth2RequestValidator tokenRequestValidator = new DefaultOAuth2RequestValidator();

    @Setter
    private OAuth2TokenEnhancer tokenEnhancer = new NullOAuth2TokenEnhancer();

    protected AbstractOAuth2TokenGranter(OAuth2TokenIdGenerator tokenIdGenerator, OAuth2AccessTokenRepository tokenRepository) {
        this.tokenIdGenerator = tokenIdGenerator;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizedAccessToken accessToken = createAccessToken(clientDetails, tokenRequest);
        tokenRepository.findByClientAndUsername(accessToken.getClient(), accessToken.getUsername()).ifPresent(tokenRepository::delete);
        tokenEnhancer.enhance(accessToken);
        tokenRepository.save(accessToken);
        return DefaultAccessTokenDetails.of(accessToken);
    }

    protected abstract OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest);

    protected LocalDateTime extractTokenExpiration(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now(clock).plusSeconds(clientDetails.getAccessTokenValiditySeconds());
    }

    protected LocalDateTime extractRefreshTokenExpiration(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now(clock).plusSeconds(clientDetails.getRefreshTokenValiditySeconds());
    }

    protected OAuth2TokenIdGenerator refreshTokenGenerator() {
        return refreshTokenIdGenerator != null ? refreshTokenIdGenerator : tokenIdGenerator;
    }

    protected Set<OAuth2ScopeId> extractGrantScope(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return (tokenRequest.getScopes() == null || tokenRequest.getScopes().isEmpty() ? clientDetails.getScopes() : tokenRequest.getScopes())
                .stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }

    private static final class NullOAuth2TokenEnhancer implements OAuth2TokenEnhancer {

        @Override
        public void enhance(OAuth2AuthorizedAccessToken accessToken) {
        }
    }
}
