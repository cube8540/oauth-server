package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.AuthenticationApplication;
import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.security.DefaultOAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2RequestValidator;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKey;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2ComposeUniqueKeyGenerator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenEnhancer;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class AbstractOAuth2TokenGranter implements OAuth2AccessTokenGranter {

    @Setter(AccessLevel.PROTECTED)
    protected static Clock clock = AuthenticationApplication.DEFAULT_CLOCK;

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

    @Setter(onMethod_ = @Autowired)
    @Getter(AccessLevel.PROTECTED)
    private OAuth2ComposeUniqueKeyGenerator composeUniqueKeyGenerator = new DefaultOAuth2ComposeUniqueKeyGenerator();

    protected AbstractOAuth2TokenGranter(OAuth2TokenIdGenerator tokenIdGenerator, OAuth2AccessTokenRepository tokenRepository) {
        this.tokenIdGenerator = tokenIdGenerator;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public OAuth2AccessTokenDetails grant(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizedAccessToken accessToken = createAccessToken(clientDetails, tokenRequest);
        Optional<OAuth2AuthorizedAccessToken> existsAccessToken = tokenRepository
                .findByComposeUniqueKey(accessToken.getComposeUniqueKey());
        if (existsAccessToken.isPresent() && isReturnsExistsToken(existsAccessToken.get(), accessToken)) {
            return DefaultAccessTokenDetails.of(existsAccessToken.get());
        }
        existsAccessToken.ifPresent(tokenRepository::delete);
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

    protected Set<AuthorityCode> extractGrantScope(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return (tokenRequest.getScopes() == null || tokenRequest.getScopes().isEmpty() ? clientDetails.getScopes() : tokenRequest.getScopes())
                .stream().map(AuthorityCode::new).collect(Collectors.toSet());
    }

    protected boolean isReturnsExistsToken(OAuth2AuthorizedAccessToken existsAccessToken, OAuth2AuthorizedAccessToken newAccessToken) {
        return existsAccessToken.getTokenGrantType().equals(newAccessToken.getTokenGrantType()) &&
                !existsAccessToken.isExpired();
    }

    private static final class NullOAuth2TokenEnhancer implements OAuth2TokenEnhancer {

        @Override
        public void enhance(OAuth2AuthorizedAccessToken accessToken) {
        }
    }

    private static final class DefaultOAuth2ComposeUniqueKeyGenerator implements OAuth2ComposeUniqueKeyGenerator {

        @Override
        public OAuth2ComposeUniqueKey generateKey(OAuth2AuthorizedAccessToken token) {
            return new OAuth2ComposeUniqueKey(token.getTokenId().getValue());
        }
    }
}
