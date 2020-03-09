package cube8540.oauth.authentication.credentials.oauth.scope.endpoint;

import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeManagementService;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeModifyRequest;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeRegisterRequest;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2AccessibleScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.error.ScopeExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@RestController
public class ScopeManagementAPIEndpoint {

    private final OAuth2ScopeManagementService managementService;
    private final OAuth2AccessibleScopeDetailsService accessibleScopeDetailsService;

    @Setter
    private ScopeExceptionTranslator translator = new ScopeExceptionTranslator();

    @Autowired
    public ScopeManagementAPIEndpoint(OAuth2ScopeManagementService managementService, OAuth2AccessibleScopeDetailsService accessibleScopeDetailsService) {
        this.managementService = managementService;
        this.accessibleScopeDetailsService = accessibleScopeDetailsService;
    }

    @GetMapping(value = "/api/scopes")
    public Map<String, Collection<OAuth2ScopeDetails>> scopes(@AuthenticationPrincipal Authentication authentication) {
        Collection<OAuth2ScopeDetails> scopes = accessibleScopeDetailsService.readAccessibleScopes(authentication);

        return Collections.singletonMap("scopes", scopes);
    }

    @PostMapping(value = "/api/scopes")
    public OAuth2ScopeDetails registerNewScopes(@RequestBody OAuth2ScopeRegisterRequest registerRequest) {
        return managementService.registerNewScope(registerRequest);
    }

    @PutMapping(value = "/api/scopes/{id}")
    public OAuth2ScopeDetails modifyScope(@PathVariable("id") String id, @RequestBody OAuth2ScopeModifyRequest modifyRequest) {
        return managementService.modifyScope(id, modifyRequest);
    }

    @DeleteMapping(value = "/api/scopes/{id}")
    public OAuth2ScopeDetails removeScope(@PathVariable("id") String id) {
        return managementService.removeScope(id);
    }

    @GetMapping(value = "/api/scopes/attributes/scopeId")
    public Map<String, Long> countScopeId(@RequestParam String scopeId) {
        Long count = managementService.countByScopeId(scopeId);

        return Collections.singletonMap("count", count);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<?>> handle(Exception e) {
        return translator.translate(e);
    }
}
