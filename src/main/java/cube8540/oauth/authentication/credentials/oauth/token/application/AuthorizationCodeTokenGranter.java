package cube8540.oauth.authentication.credentials.oauth.token.application;

import cube8540.oauth.authentication.credentials.AuthorityCode;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRepository;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizationCode;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthorizationCodeTokenGranter extends AbstractOAuth2TokenGranter {

    private final OAuth2AuthorizationCodeConsumer authorizationCodeConsumer;

    public AuthorizationCodeTokenGranter(@Qualifier("defaultTokenIdGenerator") OAuth2TokenIdGenerator tokenIdGenerator,
                                         OAuth2AccessTokenRepository tokenRepository,
                                         @Qualifier("compositionAuthorizationCodeService") OAuth2AuthorizationCodeConsumer authorizationCodeConsumer) {
        super(tokenIdGenerator, tokenRepository);
        this.authorizationCodeConsumer = authorizationCodeConsumer;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        OAuth2AuthorizationCode authorizationCode = authorizationCodeConsumer.consume(tokenRequest.getCode())
                .orElseThrow(() -> InvalidRequestException.invalidRequest("authorization code not found"));

        Set<String> authorizationCodeScope = Optional.ofNullable(authorizationCode.getApprovedScopes())
                .orElse(Collections.emptySet()).stream().map(AuthorityCode::getValue).collect(Collectors.toSet());
        if (authorizationCodeScope.isEmpty()) {
            throw InvalidGrantException.invalidScope("cannot not grant empty scope");
        }
        if (!getTokenRequestValidator().validateScopes(clientDetails, authorizationCodeScope)) {
            throw InvalidGrantException.invalidScope("cannot grant scope");
        }
        authorizationCode.validateWithAuthorizationRequest(new AuthorizationCodeRequest(clientDetails, tokenRequest));
        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(getTokenIdGenerator())
                .expiration(extractTokenExpiration(clientDetails))
                .client(authorizationCode.getClientId())
                .username(authorizationCode.getUsername())
                .scopes(authorizationCode.getApprovedScopes())
                .tokenGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .issuedAt(LocalDateTime.now(clock))
                .build();
        accessToken.generateRefreshToken(refreshTokenGenerator(), extractRefreshTokenExpiration(clientDetails));
        accessToken.generateComposeUniqueKey(getComposeUniqueKeyGenerator());
        return accessToken;
    }

    private static class AuthorizationCodeRequest implements AuthorizationRequest {

        private OAuth2ClientDetails clientDetails;
        private OAuth2TokenRequest tokenRequest;

        private AuthorizationCodeRequest(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
            this.clientDetails = clientDetails;
            this.tokenRequest = tokenRequest;
        }

        @Override
        public String getClientId() {
            return clientDetails.getClientId();
        }

        @Override
        public String getUsername() {
            return tokenRequest.getUsername();
        }

        @Override
        public String getState() {
            return tokenRequest.getState();
        }

        @Override
        public URI getRedirectUri() {
            return tokenRequest.getRedirectUri();
        }

        @Override
        public Set<String> getRequestScopes() {
            return tokenRequest.getScopes();
        }

        @Override
        public OAuth2AuthorizationResponseType getResponseType() {
            return OAuth2AuthorizationResponseType.CODE;
        }

        @Override
        public void setRedirectUri(URI redirectUri) {
            throw new UnsupportedOperationException(getClass().getName() + "#setRedirectURI");
        }

        @Override
        public void setRequestScopes(Set<String> requestScopes) {
            throw new UnsupportedOperationException(getClass().getName() + "#setRequestScopes");
        }
    }
}
