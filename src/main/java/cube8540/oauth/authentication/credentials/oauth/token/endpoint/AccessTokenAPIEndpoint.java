package cube8540.oauth.authentication.credentials.oauth.token.endpoint;

import cube8540.oauth.authentication.credentials.oauth.token.application.AccessTokenReadService;
import cube8540.oauth.authentication.credentials.oauth.token.domain.read.model.AccessTokenDetailsWithClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@RestController
public class AccessTokenAPIEndpoint {

    private final AccessTokenReadService service;

    @Autowired
    public AccessTokenAPIEndpoint(AccessTokenReadService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/tokens")
    public Map<String, List<AccessTokenDetailsWithClient>> getUserAccessToken(@AuthenticationPrincipal Authentication authentication) {
        List<AccessTokenDetailsWithClient> tokens = service.getAuthorizeAccessTokens(authentication);

        return Collections.singletonMap("tokens", tokens);
    }
}
