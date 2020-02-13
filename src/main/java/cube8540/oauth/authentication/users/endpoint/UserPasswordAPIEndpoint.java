package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
import cube8540.oauth.authentication.users.application.ChangePasswordRequest;
import cube8540.oauth.authentication.users.application.ResetPasswordRequest;
import cube8540.oauth.authentication.users.application.UserPasswordService;
import cube8540.oauth.authentication.users.application.UserProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserPasswordAPIEndpoint {

    private final UserPasswordService service;

    @Autowired
    public UserPasswordAPIEndpoint(UserPasswordService service) {
        this.service = service;
    }

    @PutMapping(value = "/api/accounts/attributes/password")
    public ResponseEntity<ResponseMessage> changePassword(Principal principal, @RequestBody ChangePasswordRequest changeRequest) {
        UserProfile user = service.changePassword(principal, changeRequest);

        ResponseMessage message = SuccessResponseMessage.ok(user);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @DeleteMapping(value = "/api/accounts/attributes/password")
    public ResponseEntity<ResponseMessage> forgotPassword(@RequestParam String email) {
        UserProfile user = service.forgotPassword(email);

        ResponseMessage message = SuccessResponseMessage.ok(user);
        return new ResponseEntity<>(message, message.getStatus());
    }

    @PostMapping(value = "/api/accounts/attributes/password")
    public ResponseEntity<ResponseMessage> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        UserProfile user = service.resetPassword(resetPasswordRequest);

        ResponseMessage message = SuccessResponseMessage.ok(user);
        return new ResponseEntity<>(message, message.getStatus());
    }
}
