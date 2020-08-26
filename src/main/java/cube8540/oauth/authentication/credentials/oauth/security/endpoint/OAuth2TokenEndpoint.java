package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.error.AbstractOAuth2AuthenticationException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.error.OAuth2ExceptionTranslator;
import cube8540.oauth.authentication.credentials.oauth.security.DefaultOAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AccessTokenGranter;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker;
import cube8540.oauth.authentication.credentials.oauth.security.provider.ClientCredentialsToken;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@Slf4j
@RestController
public class OAuth2TokenEndpoint {

    private final OAuth2AccessTokenGranter tokenGrantService;
    private final OAuth2TokenRevoker tokenRevokeService;

    @Setter(onMethod_ = {@Autowired, @Qualifier("OAuth2ExceptionTranslator")})
    private OAuth2ExceptionTranslator exceptionTranslator;

    @Autowired
    public OAuth2TokenEndpoint(@Qualifier("accessTokenGranter") OAuth2AccessTokenGranter tokenGrantService, @Qualifier("clientAuthenticationBaseTokenRevoker") OAuth2TokenRevoker tokenRevokeService) {
        this.tokenGrantService = tokenGrantService;
        this.tokenRevokeService = tokenRevokeService;
    }

    @PostMapping(value = "/oauth/token")
    public ResponseEntity<OAuth2AccessTokenDetails> grantNewAccessToken(Principal principal, @RequestParam Map<String, String> requestMap) {
        if (!(principal instanceof ClientCredentialsToken)) {
            throw new InsufficientAuthenticationException("this is no client authentication");
        }

        ClientCredentialsToken clientCredentialsToken = (ClientCredentialsToken) principal;
        if (!(clientCredentialsToken.getPrincipal() instanceof OAuth2ClientDetails)) {
            throw new InsufficientAuthenticationException("this is no client authentication");
        }

        if (requestMap.get(OAuth2Utils.TokenRequestKey.GRANT_TYPE) == null) {
            throw InvalidRequestException.invalidRequest("grant type is required");
        }

        if (requestMap.get(OAuth2Utils.TokenRequestKey.GRANT_TYPE)
                .equalsIgnoreCase(AuthorizationGrantType.IMPLICIT.getValue())) {
            throw InvalidGrantException.unsupportedGrantType("implicit grant type not supported");
        }

        OAuth2TokenRequest tokenRequest = new DefaultOAuth2TokenRequest(requestMap);
        OAuth2AccessTokenDetails token = tokenGrantService.grant((OAuth2ClientDetails) clientCredentialsToken.getPrincipal(), tokenRequest);
        return createAccessTokenResponse(token);
    }

    @DeleteMapping(value = "/oauth/token")
    public ResponseEntity<OAuth2AccessTokenDetails> revokeAccessToken(Principal principal, @RequestParam(required =  false) String token) {
        if (!(principal instanceof ClientCredentialsToken)) {
            throw new InsufficientAuthenticationException("this is no client authentication");
        }
        if (token == null) {
            throw InvalidRequestException.invalidRequest("Token is required");
        }

        OAuth2AccessTokenDetails accessToken = tokenRevokeService.revoke(token);
        return createAccessTokenResponse(accessToken);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<OAuth2Error> handleException(Exception e) {
        log.error("Handling error: {}, {}", e.getClass(), e.getMessage());
        return exceptionTranslator.translate(e);
    }

    @ExceptionHandler(AbstractOAuth2AuthenticationException.class)
    public ResponseEntity<OAuth2Error> handleException(AbstractOAuth2AuthenticationException e) {
        log.warn("Handling error: {}, {}", e.getClass(), e.getMessage());
        return exceptionTranslator.translate(e);
    }

    private ResponseEntity<OAuth2AccessTokenDetails> createAccessTokenResponse(OAuth2AccessTokenDetails token) {
        HttpHeaders headers = new HttpHeaders();

        headers.setCacheControl(CacheControl.noStore());
        headers.setPragma("no-cache");
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new ResponseEntity<>(token, headers, HttpStatus.OK);
    }
}
