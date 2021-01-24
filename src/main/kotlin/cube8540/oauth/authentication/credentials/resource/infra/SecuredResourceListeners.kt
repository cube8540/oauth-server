package cube8540.oauth.authentication.credentials.resource.infra

import cube8540.oauth.authentication.credentials.resource.domain.SecuredResourceChangedEvent
import cube8540.oauth.authentication.credentials.security.ReloadableFilterInvocationSecurityMetadataSource
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Component
import org.springframework.transaction.event.TransactionPhase
import org.springframework.transaction.event.TransactionalEventListener

@Component
class SecuredObjectChangedEventListener @Autowired constructor(
    private val reloadableMetadataSource: ReloadableFilterInvocationSecurityMetadataSource
) {

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, classes = [SecuredResourceChangedEvent::class])
    fun reloadMetadataSource() = reloadableMetadataSource.reload()
}