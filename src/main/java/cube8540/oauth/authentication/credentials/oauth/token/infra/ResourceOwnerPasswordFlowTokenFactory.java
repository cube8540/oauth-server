package cube8540.oauth.authentication.credentials.oauth.token.infra;

import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.domain.OAuth2ClientId;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2TokenRequestValidator;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AuthorizedAccessToken;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenFactory;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2TokenIdGenerator;
import cube8540.oauth.authentication.users.domain.UserEmail;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.stream.Collectors;

public class ResourceOwnerPasswordFlowTokenFactory implements OAuth2TokenFactory {

    private final OAuth2TokenIdGenerator tokenIdGenerator;
    private final AuthenticationManager authenticationManager;

    private OAuth2TokenIdGenerator refreshTokenIdGenerator;
    private OAuth2TokenRequestValidator validator = new DefaultOAuth2TokenRequestValidator();

    public ResourceOwnerPasswordFlowTokenFactory(OAuth2TokenIdGenerator tokenIdGenerator, AuthenticationManager authenticationManager) {
        this.tokenIdGenerator = tokenIdGenerator;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public OAuth2AuthorizedAccessToken createAccessToken(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        if (tokenRequest.username() == null || tokenRequest.password() == null) {
            throw new InvalidRequestException("username, password is required");
        }
        if (!validator.validateScopes(clientDetails, tokenRequest)) {
            throw new InvalidGrantException("cannot grant scopes");
        }
        Authentication authentication = authentication(tokenRequest);
        OAuth2AuthorizedAccessToken accessToken = OAuth2AuthorizedAccessToken.builder(tokenIdGenerator)
                .expiration(extractTokenExpirationDateTime(clientDetails))
                .client(new OAuth2ClientId(clientDetails.clientId()))
                .email(new UserEmail(authentication.getPrincipal().toString()))
                .scope(extractGrantedScope(clientDetails, tokenRequest))
                .tokenGrantType(AuthorizationGrantType.PASSWORD)
                .build();
        accessToken.generateRefreshToken(extractRefreshTokenIdGenerator(), extractRefreshTokenExpirationDateTime(clientDetails));
        return accessToken;
    }

    private Authentication authentication(OAuth2TokenRequest tokenRequest) {
        try {
            UsernamePasswordAuthenticationToken usernamePasswordToken =
                    new UsernamePasswordAuthenticationToken(tokenRequest.username(), tokenRequest.password());
            return authenticationManager.authenticate(usernamePasswordToken);
        } catch (BadCredentialsException | AccountStatusException e) {
            throw new InvalidGrantException(e.getMessage());
        }
    }

    private OAuth2TokenIdGenerator extractRefreshTokenIdGenerator() {
        return refreshTokenIdGenerator != null ? refreshTokenIdGenerator : tokenIdGenerator;
    }

    private Set<OAuth2ScopeId> extractGrantedScope(OAuth2ClientDetails clientDetails, OAuth2TokenRequest tokenRequest) {
        return (tokenRequest.scopes() == null || tokenRequest.scopes().isEmpty() ? clientDetails.scope() : tokenRequest.scopes())
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
