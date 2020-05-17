package cube8540.oauth.authentication.users.infra.listener;

import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.domain.UserRegisterEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class UserRegisteredEventListener {

    private final UserCredentialsService credentialsService;

    @Autowired
    public UserRegisteredEventListener(UserCredentialsService credentialsService) {
        this.credentialsService = credentialsService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMPLETION, classes = UserRegisterEvent.class)
    public void handle(UserRegisterEvent event) {
        credentialsService.grantCredentialsKey(event.getUsername().getValue());
    }
}
