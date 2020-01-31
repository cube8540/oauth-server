package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.DefaultOAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2TokenRequest;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.client.OAuth2ClientDetails;
import cube8540.oauth.authentication.credentials.oauth.client.provider.ClientCredentialsToken;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidGrantException;
import cube8540.oauth.authentication.credentials.oauth.error.InvalidRequestException;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenDetails;
import cube8540.oauth.authentication.credentials.oauth.token.OAuth2AccessTokenGrantService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class OAuth2TokenEndpoint {

    private final OAuth2AccessTokenGrantService tokenGrantService;

    @Autowired
    public OAuth2TokenEndpoint(OAuth2AccessTokenGrantService tokenGrantService) {
        this.tokenGrantService = tokenGrantService;
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
            throw new InvalidRequestException("grant type required");
        }

        if (requestMap.get(OAuth2Utils.TokenRequestKey.GRANT_TYPE)
                .equalsIgnoreCase(AuthorizationGrantType.IMPLICIT.getValue())) {
            throw new InvalidGrantException("implicit grant type not supported");
        }

        OAuth2TokenRequest tokenRequest = new DefaultOAuth2TokenRequest(requestMap);
        OAuth2AccessTokenDetails token = tokenGrantService.grant((OAuth2ClientDetails) clientCredentialsToken.getPrincipal(), tokenRequest);
        return createAccessTokenResponse(token);
    }

    private ResponseEntity<OAuth2AccessTokenDetails> createAccessTokenResponse(OAuth2AccessTokenDetails token) {
        HttpHeaders headers = new HttpHeaders();

        headers.setCacheControl(CacheControl.noStore());
        headers.setPragma("no-cache");
        headers.setContentType(MediaType.APPLICATION_JSON);
        return new ResponseEntity<>(token, headers, HttpStatus.OK);
    }
}
