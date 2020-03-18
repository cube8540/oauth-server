package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenDetails;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2TokenRevoker;
import cube8540.oauth.authentication.credentials.oauth.token.application.AccessTokenReadService;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class AccessTokenAPIEndpoint {

    private final AccessTokenReadService service;
    private final OAuth2TokenRevoker revoker;

    @Setter(onMethod_ = {@Autowired, @Qualifier("tokenExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public AccessTokenAPIEndpoint(AccessTokenReadService service, @Qualifier("userAuthenticationBaseTokenRevoker") OAuth2TokenRevoker revoker) {
        this.service = service;
        this.revoker = revoker;
    }

    @GetMapping(value = "/api/tokens")
    public Map<String, List<AccessTokenDetailsWithClient>> getUserAccessToken(@AuthenticationPrincipal Authentication authentication) {
        List<AccessTokenDetailsWithClient> tokens = service.getAuthorizeAccessTokens(authentication);

        return Collections.singletonMap("tokens", tokens);
    }

    @DeleteMapping(value = "/api/tokens/{accessToken}")
    public OAuth2TokenDetails deleteUserAccessToken(@PathVariable("accessToken") String accessToken) {
        return revoker.revoke(accessToken);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> exceptionHandling(Exception e) {
        return translator.translate(e);
    }
}
