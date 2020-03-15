package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.domain.exception.UserNotFoundException;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;

import java.util.Map;

@RestController
@SessionAttributes({UserManagementAPIEndpoint.NEW_REGISTERED_USER_ATTRIBUTE})
public class UserCredentialsAPIEndpoint {

    private final UserCredentialsService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("userExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public UserCredentialsAPIEndpoint(UserCredentialsService service) {
        this.service = service;
    }

    @PutMapping(value = "/api/accounts/attributes/active")
    public UserProfile credentials(@RequestParam String credentialsKey, Map<String, Object> model, SessionStatus sessionStatus) {
        try {
            if (model.get(UserManagementAPIEndpoint.NEW_REGISTERED_USER_ATTRIBUTE) == null) {
                throw UserNotFoundException.instance("Registered user is not found");
            }
            UserProfile registeredUser = (UserProfile) model.get(UserManagementAPIEndpoint.NEW_REGISTERED_USER_ATTRIBUTE);
            return service.accountCredentials(registeredUser.getEmail(), credentialsKey);
        } finally {
            sessionStatus.setComplete();
        }
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
