package cube8540.oauth.authentication.credentials.authority.endpoint;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityModifyRequest;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityRegisterRequest;
import cube8540.oauth.authentication.credentials.authority.error.AuthorityExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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
public class AuthorityManagementAPIEndpoint {

    private final AuthorityManagementService service;

    @Setter
    private AuthorityExceptionTranslator translator = new AuthorityExceptionTranslator();

    @Autowired
    public AuthorityManagementAPIEndpoint(AuthorityManagementService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/authorities/attributes/code")
    public Map<String, Long> countingAuthorityCode(@RequestParam("code") String authorityCode) {
        long count = service.countAuthority(authorityCode);

        return Collections.singletonMap("count", count);
    }

    @GetMapping(value = "/api/authorities/{code}")
    public AuthorityDetails getAuthorityDetails(@PathVariable("code") String authorityCode) {
        return service.getAuthority(authorityCode);
    }

    @GetMapping(value = "/api/authorities")
    public Map<String, Collection<AuthorityDetails>> getAuthorities() {
        Collection<AuthorityDetails> authorities = service.getAuthorities();

        return Collections.singletonMap("authorities", authorities);
    }

    @PostMapping(value = "/api/authorities")
    public AuthorityDetails registerAuthority(@RequestBody AuthorityRegisterRequest registerRequest) {
        return service.registerAuthority(registerRequest);
    }

    @PutMapping(value = "/api/authorities/{code}")
    public AuthorityDetails modifyAuthority(@PathVariable("code") String code, @RequestBody AuthorityModifyRequest modifyRequest) {
        return service.modifyAuthority(code, modifyRequest);
    }

    @DeleteMapping(value = "/api/authorities/{code}")
    public AuthorityDetails removeAuthority(@PathVariable("code") String code) {
        return service.removeAuthority(code);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<?>> handle(Exception e) {
        return translator.translate(e);
    }
}
