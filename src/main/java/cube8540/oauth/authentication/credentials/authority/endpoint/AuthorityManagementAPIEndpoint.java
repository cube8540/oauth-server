package cube8540.oauth.authentication.credentials.authority.endpoint;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityModifyRequest;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityRegisterRequest;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityAlreadyException;
import cube8540.oauth.authentication.credentials.authority.domain.AuthorityNotFoundException;
import cube8540.oauth.authentication.message.ErrorResponseMessage;
import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
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

@RestController
public class AuthorityManagementAPIEndpoint {

    private final AuthorityManagementService service;

    @Autowired
    public AuthorityManagementAPIEndpoint(AuthorityManagementService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/authorities/attributes/code")
    public ResponseEntity<ResponseMessage> countingAuthorityCode(@RequestParam("code") String authorityCode) {
        long count = service.countAuthority(authorityCode);

        ResponseMessage message = SuccessResponseMessage.ok(count);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @GetMapping(value = "/api/authorities/{code}")
    public ResponseEntity<ResponseMessage> getAuthorityDetails(@PathVariable("code") String authorityCode) {
        AuthorityDetails authority = service.getAuthority(authorityCode);

        ResponseMessage message = SuccessResponseMessage.ok(authority);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @GetMapping(value = "/api/authorities")
    public ResponseEntity<ResponseMessage> getAuthorities() {
        Collection<AuthorityDetails> authorities = service.getAuthorities();

        ResponseMessage message = SuccessResponseMessage.ok(authorities);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PostMapping(value = "/api/authorities")
    public ResponseEntity<ResponseMessage> registerAuthority(@RequestBody AuthorityRegisterRequest registerRequest) {
        AuthorityDetails authority = service.registerAuthority(registerRequest);

        ResponseMessage message = SuccessResponseMessage.created(authority);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PutMapping(value = "/api/authorities/{code}")
    public ResponseEntity<ResponseMessage> modifyAuthority(@PathVariable("code") String code, @RequestBody AuthorityModifyRequest modifyRequest) {
        AuthorityDetails authority = service.modifyAuthority(code, modifyRequest);

        ResponseMessage message = SuccessResponseMessage.ok(authority);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @DeleteMapping(value = "/api/authorities/{code}")
    public ResponseEntity<ResponseMessage> removeAuthority(@PathVariable("code") String code) {
        AuthorityDetails authority = service.removeAuthority(code);

        ResponseMessage message = SuccessResponseMessage.ok(authority);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(AuthorityAlreadyException.class)
    public ResponseEntity<ResponseMessage> handle(AuthorityAlreadyException e) {
        ResponseMessage message = ErrorResponseMessage.conflict(e.getMessage());
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(AuthorityNotFoundException.class)
    public ResponseEntity<ResponseMessage> handle(AuthorityNotFoundException e) {
        ResponseMessage message = ErrorResponseMessage.notfound(e.getMessage());
        return new ResponseEntity<>(message, message.getStatus());
    }
}
