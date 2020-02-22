package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.ErrorMessage;
import cube8540.oauth.authentication.users.application.UserManagementService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.application.UserRegisterRequest;
import cube8540.oauth.authentication.users.error.UserExceptionTranslator;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class UserManagementAPIEndpoint {

    private final UserManagementService service;

    @Setter
    private UserExceptionTranslator translator = new UserExceptionTranslator();

    @Autowired
    public UserManagementAPIEndpoint(UserManagementService service) {
        this.service = service;
    }

    @PostMapping(value = "/api/accounts")
    public UserProfile registerUserAccounts(@RequestBody UserRegisterRequest registerRequest) {
        return service.registerUser(registerRequest);
    }

    @GetMapping(value = "/api/accounts/attributes/email")
    public Map<String, Long> countAccountEmail(@RequestParam("email") String email) {
        long count = service.countUser(email);
        return Collections.singletonMap("count", count);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<?>> handle(Exception e) {
        return translator.translate(e);
    }
}
