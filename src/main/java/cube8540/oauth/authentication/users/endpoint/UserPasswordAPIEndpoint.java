package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.message.ExceptionTranslator;
import cube8540.oauth.authentication.users.application.ChangePasswordRequest;
import cube8540.oauth.authentication.users.application.ResetPasswordRequest;
import cube8540.oauth.authentication.users.application.UserPasswordService;
import cube8540.oauth.authentication.users.application.UserProfile;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserPasswordAPIEndpoint {

    private final UserPasswordService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("userExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public UserPasswordAPIEndpoint(UserPasswordService service) {
        this.service = service;
    }

    @PutMapping(value = "/api/accounts/attributes/password")
    public UserProfile changePassword(Principal principal, @RequestBody ChangePasswordRequest changeRequest) {
        return service.changePassword(principal, changeRequest);
    }

    @DeleteMapping(value = "/api/accounts/attributes/password")
    public UserProfile forgotPassword(@RequestParam String email) {
        return service.forgotPassword(email);
    }

    @PostMapping(value = "/api/accounts/attributes/password")
    public UserProfile resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        return service.resetPassword(resetPasswordRequest);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
