package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.message.ErrorResponseMessage;
import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
import cube8540.oauth.authentication.users.application.UserManagementService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.application.UserRegisterRequest;
import cube8540.oauth.authentication.users.domain.UserAlreadyExistsException;
import cube8540.oauth.authentication.users.domain.UserInvalidException;
import cube8540.oauth.authentication.users.domain.UserNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserManagementAPIEndpoint {

    private final UserManagementService service;

    @Autowired
    public UserManagementAPIEndpoint(UserManagementService service) {
        this.service = service;
    }

    @PostMapping(value = "/api/accounts")
    public ResponseEntity<ResponseMessage> registerUserAccounts(@RequestBody UserRegisterRequest registerRequest) {
        UserProfile registerUser = service.registerUser(registerRequest);

        ResponseMessage message = SuccessResponseMessage.created(registerUser);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @GetMapping(value = "/api/accounts/attributes/email")
    public ResponseEntity<ResponseMessage> countAccountEmail(@RequestParam("email") String email) {
        long count = service.countUser(email);

        ResponseMessage message = SuccessResponseMessage.ok(count);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(UserInvalidException.class)
    public ResponseEntity<ResponseMessage> exceptionHandle(UserInvalidException e) {
        ResponseMessage message = ErrorResponseMessage.badRequest(e.getErrors());
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ResponseMessage> exceptionHandle(UserAlreadyExistsException e) {
        ResponseMessage message = ErrorResponseMessage.conflict(e.getMessage());
        return new ResponseEntity<>(message, message.getStatus());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ResponseMessage> exceptionHandle(UserNotFoundException e) {
        ResponseMessage message = ErrorResponseMessage.notfound(e.getMessage());
        return new ResponseEntity<>(message, message.getStatus());
    }
}
