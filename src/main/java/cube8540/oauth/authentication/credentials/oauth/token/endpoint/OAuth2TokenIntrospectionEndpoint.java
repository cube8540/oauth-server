package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.token.application.OAuth2AccessTokenReadService;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.error.AbstractOAuth2AuthenticationException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.domain.OAuth2AccessTokenRegistrationException;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@Slf4j
@RestController
public class OAuth2TokenIntrospectionEndpoint {

    private final OAuth2AccessTokenReadService service;

    @Setter
    private OAuth2ExceptionTranslator exceptionTranslator = new OAuth2ExceptionTranslator();

    @Setter
    private OAuth2AccessTokenIntrospectionConverter converter = new DefaultOAuth2AccessTokenIntrospectionConverter();

    @Autowired
    public OAuth2TokenIntrospectionEndpoint(OAuth2AccessTokenReadService service) {
        this.service = service;
    }

    @PostMapping(value = "/oauth/token_info")
    public Map<String, Object> introspection(Principal principal, @RequestParam(required = false) String token) {
        if (token == null) {
            throw InvalidRequestException.invalidRequest("access token is required");
        }

        if (!(principal instanceof ClientCredentialsToken)) {
            throw new InsufficientAuthenticationException("this is no client authentication");
        }

        ClientCredentialsToken clientCredentials = (ClientCredentialsToken) principal;
        if (!(clientCredentials.getPrincipal() instanceof OAuth2ClientDetails)) {
            throw new InsufficientAuthenticationException("this is no client authentication");
        }

        OAuth2AccessTokenDetails accessToken = service.readAccessToken(token);
        return converter.convertAccessToken(accessToken);
    }

    @GetMapping(value = "/oauth/user_info")
    public UserDetails userInfo(Principal principal, @RequestParam(required = false) String token) {
        if (token == null) {
            throw InvalidRequestException.invalidRequest("access token is required");
        }

        if (!(principal instanceof ClientCredentialsToken)) {
            throw new InsufficientAuthenticationException("this is no client authentication");
        }

        return service.readAccessTokenUser(token);
    }

    @ExceptionHandler(OAuth2AccessTokenRegistrationException.class)
    public ResponseEntity<OAuth2Error> handleException(OAuth2AccessTokenRegistrationException e) {
        log.warn("Handling error {}, {}", e.getClass(), e.getMessage());
        return exceptionTranslator.translate(e);
    }

    @ExceptionHandler(AbstractOAuth2AuthenticationException.class)
    public ResponseEntity<OAuth2Error> handleException(AbstractOAuth2AuthenticationException e) {
        log.warn("Handling error {}, {}", e.getClass(), e.getMessage());
        return exceptionTranslator.translate(e);
    }

    @ExceptionHandler(Exception.class)
    public Map<String, Boolean> handleServerException(Exception e) {
        log.error("Handling error {}, {}", e.getClass(), e.getMessage());
        return Collections.singletonMap(OAuth2Utils.AccessTokenIntrospectionKey.ACTIVE, false);
    }
}
