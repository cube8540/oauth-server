package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.DefaultOAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.code.application.OAuth2AuthorizationCodeService;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.code.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizationCodeTokenFactory implements OAuth2TokenFactory {

    private final OAuth2TokenIdGenerator tokenIdGenerator;
    private final OAuth2AuthorizationCodeService authorizationCodeService;

    private OAuth2TokenIdGenerator refreshTokenIdGenerator;

    private OAuth2TokenRequestValidator validator = new DefaultOAuth2TokenRequestValidator();

    public AuthorizationCodeTokenFactory(OAuth2TokenIdGenerator tokenIdGenerator, OAuth2AuthorizationCodeService authorizationCodeService) {
        this.tokenIdGenerator = tokenIdGenerator;
        this.authorizationCodeService = authorizationCodeService;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizationCode authorizationCode = authorizationCodeService.consume(new AuthorizationCode(tokenRequest.code()))
                .orElseThrow(() -> new InvalidRequestException("authorization code not found"));

        Set<String> authorizationCodeScope = Optional.ofNullable(authorizationCode.getApprovedScopes())
                .orElse(Collections.emptySet()).stream().map(OAuth2ScopeId::getValue).collect(Collectors.toSet());
        if (!validator.validateScopes(clientDetails, authorizationCodeScope)) {
            throw new InvalidGrantException("cannot grant scopes");
        }
        authorizationCode.validateWithAuthorizationRequest(new AuthorizationCodeRequest(tokenRequest));
        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                .expiration(extractExpirationDateTime(clientDetails))
                .client(authorizationCode.getClientId())
                .email(authorizationCode.getEmail())
                .scope(extractScope(clientDetails, authorizationCode))
                .tokenGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
        accessToken.generateRefreshToken(extractRefreshTokenIdGenerator(), extractRefreshTokenExpirationDateTime(clientDetails));
        return accessToken;
    }

    public void setRefreshTokenIdGenerator(OAuth2TokenIdGenerator refreshTokenIdGenerator) {
        this.refreshTokenIdGenerator = refreshTokenIdGenerator;
    }

    public void setValidator(OAuth2TokenRequestValidator validator) {
        this.validator = validator;
    }

    private LocalDateTime extractExpirationDateTime(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.accessTokenValiditySeconds());
    }

    private LocalDateTime extractRefreshTokenExpirationDateTime(OAuth2ClientDetails clientDetails) {
        return LocalDateTime.now().plusSeconds(clientDetails.refreshTokenValiditySeconds());
    }

    private Set<OAuth2ScopeId> extractScope(OAuth2ClientDetails clientDetails, OAuth2AuthorizationCode code) {
        if (code.getApprovedScopes() == null || code.getApprovedScopes().isEmpty()) {
            return clientDetails.scope().stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
        }
        return code.getApprovedScopes();
    }

    private OAuth2TokenIdGenerator extractRefreshTokenIdGenerator() {
        return refreshTokenIdGenerator != null ? refreshTokenIdGenerator : tokenIdGenerator;
    }

    private static class AuthorizationCodeRequest implements AuthorizationRequest {

        private OAuth2TokenRequest tokenRequest;

        private AuthorizationCodeRequest(OAuth2TokenRequest tokenRequest) {
            this.tokenRequest = tokenRequest;
        }

        @Override
        public String clientId() {
            return tokenRequest.clientId();
        }

        @Override
        public String email() {
            return tokenRequest.username();
        }

        @Override
        public String state() {
            return null;
        }

        @Override
        public URI redirectURI() {
            return tokenRequest.redirectURI();
        }

        @Override
        public Set<String> approvedScopes() {
            return tokenRequest.scopes();
        }
    }
}
