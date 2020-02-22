package cube8540.oauth.authentication.credentials.oauth.scope.endpoint;

import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2AccessibleScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.OAuth2ScopeDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeManagementService;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeModifyRequest;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeRegisterRequest;
import cube8540.oauth.authentication.credentials.oauth.scope.error.ScopeExceptionTranslator;
import cube8540.oauth.authentication.error.ErrorMessage;
import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
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
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

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
    public ResponseEntity<ResponseMessage> scopes(@AuthenticationPrincipal Authentication authentication) {
        Collection<OAuth2ScopeDetails> scopes = accessibleScopeDetailsService.readAccessibleScopes(authentication);

        ResponseMessage message = SuccessResponseMessage.ok(scopes);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PostMapping(value = "/api/scopes")
    public ResponseEntity<ResponseMessage> registerNewScopes(@RequestBody OAuth2ScopeRegisterRequest registerRequest) {
        OAuth2ScopeDetails scope = managementService.registerNewScope(registerRequest);

        ResponseMessage message = SuccessResponseMessage.ok(scope);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PutMapping(value = "/api/scopes/{id}")
    public ResponseEntity<ResponseMessage> modifyScope(@PathVariable("id") String id, @RequestBody OAuth2ScopeModifyRequest modifyRequest) {
        OAuth2ScopeDetails scope = managementService.modifyScope(id, modifyRequest);

        ResponseMessage message = SuccessResponseMessage.ok(scope);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @DeleteMapping(value = "/api/scopes/{id}")
    public ResponseEntity<ResponseMessage> removeScope(@PathVariable("id") String id) {
        OAuth2ScopeDetails scope = managementService.removeScope(id);

        ResponseMessage message = SuccessResponseMessage.ok(scope);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<?>> handle(Exception e) {
        return translator.translate(e);
    }
}
