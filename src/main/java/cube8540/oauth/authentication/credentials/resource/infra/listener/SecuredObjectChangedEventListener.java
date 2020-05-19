package cube8540.oauth.authentication.credentials.resource.infra.listener;

import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceChangedEvent;
import cube8540.oauth.authentication.credentials.security.ReloadableFilterInvocationSecurityMetadataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class SecuredObjectChangedEventListener {

    private final ReloadableFilterInvocationSecurityMetadataSource reloadableMetadataSource;

    @Autowired
    public SecuredObjectChangedEventListener(ReloadableFilterInvocationSecurityMetadataSource reloadableMetadataSource) {
        this.reloadableMetadataSource = reloadableMetadataSource;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, classes = {SecuredResourceChangedEvent.class})
    public void reloadMetadataSource() {
        this.reloadableMetadataSource.reload();
    }
}
