package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.application.UserProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserCredentialsAPIEndpoint {

    private final UserCredentialsService service;

    @Autowired
    public UserCredentialsAPIEndpoint(UserCredentialsService service) {
        this.service = service;
    }

    @PutMapping(value = "/api/accounts/credentials/{email}")
    public ResponseEntity<ResponseMessage> credentials(@PathVariable("email") String email, @RequestParam String credentialsKey) {
        UserProfile credentialsUser = service.accountCredentials(email, credentialsKey);

        SuccessResponseMessage<UserProfile> message = SuccessResponseMessage.ok(credentialsUser);
        return new ResponseEntity<>(message, message.getStatus());
    }
}
