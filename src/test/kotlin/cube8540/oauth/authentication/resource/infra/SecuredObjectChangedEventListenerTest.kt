package cube8540.oauth.authentication.resource.infra

import cube8540.oauth.authentication.security.ReloadableFilterInvocationSecurityMetadataSource
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test

class SecuredObjectChangedEventListenerTest {

    private val metadataSource: ReloadableFilterInvocationSecurityMetadataSource = mockk(relaxed = true)

    private val listener: SecuredObjectChangedEventListener = SecuredObjectChangedEventListener(metadataSource)

    @Test
    fun `reloading metadata source`() {
        listener.reloadMetadataSource()

        verify { metadataSource.reload() }
    }

}