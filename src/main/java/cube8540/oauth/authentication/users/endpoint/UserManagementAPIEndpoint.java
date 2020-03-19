package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.users.application.UserManagementService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.application.UserRegisterRequest;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttributes;

import java.util.Collections;
import java.util.Map;

@RestController
@SessionAttributes({UserManagementAPIEndpoint.NEW_REGISTERED_USER_ATTRIBUTE})
public class UserManagementAPIEndpoint {

    protected static final String NEW_REGISTERED_USER_ATTRIBUTE = "UserManagementAPIEndpoint.newRegisteredUser";

    private final UserManagementService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("userExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public UserManagementAPIEndpoint(UserManagementService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/accounts/me")
    public UserProfile getProfile(@AuthenticationPrincipal Authentication authentication) {
        return service.loadUserProfile(authentication.getName());
    }

    @PostMapping(value = "/api/accounts")
    public UserProfile registerUserAccounts(@RequestBody UserRegisterRequest registerRequest, Map<String, Object> model) {
        UserProfile registerUser = service.registerUser(registerRequest);

        model.put(NEW_REGISTERED_USER_ATTRIBUTE, registerUser);
        return registerUser;
    }

    @GetMapping(value = "/api/accounts/attributes/email")
    public Map<String, Long> countAccountEmail(@RequestParam("email") String email) {
        long count = service.countUser(email);
        return Collections.singletonMap("count", count);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
