package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedRefreshToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2RefreshTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

public class RefreshFlowTokenFactory implements OAuth2TokenFactory {

    private final OAuth2RefreshTokenRepository refreshTokenRepository;
    private final OAuth2TokenIdGenerator tokenIdGenerator;

    private OAuth2TokenIdGenerator refreshTokenIdGenerator;
    private OAuth2TokenRequestValidator validator = new DefaultOAuth2TokenRequestValidator();

    public RefreshFlowTokenFactory(OAuth2RefreshTokenRepository refreshTokenRepository,
                                   OAuth2TokenIdGenerator tokenIdGenerator) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenIdGenerator = tokenIdGenerator;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (!validator.validateScopes(clientDetails, tokenRequest)) {
            throw new InvalidGrantException("cannot grant scopes");
        }
        OAuth2AuthorizedRefreshToken storedRefreshToken = refreshTokenRepository.findById(new OAuth2TokenId(tokenRequest.refreshToken()))
                .orElseThrow(() -> new InvalidGrantException("invalid refresh token"));
        if (storedRefreshToken.isExpired()) {
            throw new InvalidGrantException("refresh token is expired");
        }

        OAuth2AuthorizedAccessToken storedAccessToken = storedRefreshToken.getAccessToken();
        if (!storedAccessToken.getClient().equals(new OAuth2ClientId(clientDetails.clientId()))) {
            throw new InvalidGrantException("invalid refresh token");
        }
        refreshTokenRepository.delete(storedRefreshToken);

        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                .expiration(extractTokenExpirationDateTime(clientDetails))
                .client(storedAccessToken.getClient())
                .email(storedAccessToken.getEmail())
                .scope(extractGrantedScopes(clientDetails, tokenRequest))
                .tokenGrantType(storedAccessToken.getTokenGrantType())
                .build();
        accessToken.generateRefreshToken(extractRefreshTokenIdGenerator(), extractRefreshTokenExpirationDateTime(clientDetails));
        return accessToken;
    }

    private OAuth2TokenIdGenerator extractRefreshTokenIdGenerator() {
        return refreshTokenIdGenerator != null ? refreshTokenIdGenerator : tokenIdGenerator;
    }

    private Set<OAuth2ScopeId> extractGrantedScopes(OAuth2ClientDetails clientDetails, OAuth2TokenRequest request) {
        return ((request.scopes() == null || request.scopes().isEmpty()) ? clientDetails.scope() : request.scopes())
                .stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
    }

    private LocalDateTime extractTokenExpirationDateTime(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.accessTokenValiditySeconds());
    }

    private LocalDateTime extractRefreshTokenExpirationDateTime(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.refreshTokenValiditySeconds());
    }

    public void setValidator(OAuth2TokenRequestValidator validator) {
        this.validator = validator;
    }

    public void setRefreshTokenIdGenerator(OAuth2TokenIdGenerator refreshTokenIdGenerator) {
        this.refreshTokenIdGenerator = refreshTokenIdGenerator;
    }
}
