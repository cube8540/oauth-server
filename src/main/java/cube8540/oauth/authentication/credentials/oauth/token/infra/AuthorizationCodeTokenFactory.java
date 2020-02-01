package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.code.application.OAuth2AuthorizationCodeConsumer;
import cube8540.oauth.authentication.credentials.oauth.code.domain.AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.code.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.net.URI;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthorizationCodeTokenFactory extends AbstractOAuth2TokenFactory {

    private final OAuth2AuthorizationCodeConsumer authorizationCodeConsumer;

    public AuthorizationCodeTokenFactory(OAuth2TokenIdGenerator tokenIdGenerator, OAuth2AuthorizationCodeConsumer authorizationCodeConsumer) {
        super(tokenIdGenerator);
        this.authorizationCodeConsumer = authorizationCodeConsumer;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizationCode authorizationCode = authorizationCodeConsumer.consume(new AuthorizationCode(tokenRequest.code()))
                .orElseThrow(() -> new InvalidRequestException("authorization code not found"));

        Set<String> authorizationCodeScope = Optional.ofNullable(authorizationCode.getApprovedScopes())
                .orElse(Collections.emptySet()).stream().map(OAuth2ScopeId::getValue).collect(Collectors.toSet());
        if (!getTokenRequestValidator().validateScopes(clientDetails, authorizationCodeScope)) {
            throw new InvalidGrantException("cannot grant scopes");
        }
        authorizationCode.validateWithAuthorizationRequest(new AuthorizationCodeRequest(tokenRequest));
        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .expiration(extractTokenExpiration(clientDetails))
                .client(authorizationCode.getClientId())
                .email(authorizationCode.getEmail())
                .scope(extractGrantScope(clientDetails, authorizationCode))
                .tokenGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails));
        return accessToken;
    }

    private Set<OAuth2ScopeId> extractGrantScope(OAuth2ClientDetails clientDetails, OAuth2AuthorizationCode code) {
        if (code.getApprovedScopes() == null || code.getApprovedScopes().isEmpty()) {
            return clientDetails.scope().stream().map(OAuth2ScopeId::new).collect(Collectors.toSet());
        }
        return code.getApprovedScopes();
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
