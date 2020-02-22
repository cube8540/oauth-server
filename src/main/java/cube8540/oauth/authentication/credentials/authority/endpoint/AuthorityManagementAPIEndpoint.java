package cube8540.oauth.authentication.credentials.authority.endpoint;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityModifyRequest;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityRegisterRequest;
import cube8540.oauth.authentication.credentials.authority.error.AuthorityExceptionTranslator;
import cube8540.oauth.authentication.error.ErrorMessage;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
    public ResponseEntity<Map<String, Long>> countingAuthorityCode(@RequestParam("code") String authorityCode) {
        long count = service.countAuthority(authorityCode);

        Map<String, Long> message = Collections.singletonMap("count", count);
        return createResponse(message);
    }

    @GetMapping(value = "/api/authorities/{code}")
    public ResponseEntity<AuthorityDetails> getAuthorityDetails(@PathVariable("code") String authorityCode) {
        AuthorityDetails authority = service.getAuthority(authorityCode);

        return createResponse(authority);
    }

    @GetMapping(value = "/api/authorities")
    public ResponseEntity<Map<String, Collection<AuthorityDetails>>> getAuthorities() {
        Collection<AuthorityDetails> authorities = service.getAuthorities();

        Map<String, Collection<AuthorityDetails>> message = Collections.singletonMap("authorities", authorities);
        return createResponse(message);
    }

    @PostMapping(value = "/api/authorities")
    public ResponseEntity<AuthorityDetails> registerAuthority(@RequestBody AuthorityRegisterRequest registerRequest) {
        AuthorityDetails authority = service.registerAuthority(registerRequest);

        return createResponse(authority);
    }

    @PutMapping(value = "/api/authorities/{code}")
    public ResponseEntity<AuthorityDetails> modifyAuthority(@PathVariable("code") String code, @RequestBody AuthorityModifyRequest modifyRequest) {
        AuthorityDetails authority = service.modifyAuthority(code, modifyRequest);

        return createResponse(authority);
    }

    @DeleteMapping(value = "/api/authorities/{code}")
    public ResponseEntity<AuthorityDetails> removeAuthority(@PathVariable("code") String code) {
        AuthorityDetails authority = service.removeAuthority(code);

        return createResponse(authority);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<?>> handle(Exception e) {
        return translator.translate(e);
    }

    private <T> ResponseEntity<T> createResponse(T response) {
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
