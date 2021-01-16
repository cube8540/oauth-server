package cube8540.oauth.authentication.credentials.resource.infra;

import cube8540.oauth.authentication.credentials.security.ReloadableFilterInvocationSecurityMetadataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class SecuredObjectChangedEventListenerTest {

    private ReloadableFilterInvocationSecurityMetadataSource metadataSource;
    private SecuredObjectChangedEventListener listener;

    @BeforeEach
    void setup() {
        this.metadataSource = mock(ReloadableFilterInvocationSecurityMetadataSource.class);
        this.listener = new SecuredObjectChangedEventListener(metadataSource);
    }

    @Test
    @DisplayName("이벤트 발생시 메타 데이터를 리로딩 해야 한다.")
    void listeningEventReloadingToMetadataSource() {
        listener.reloadMetadataSource();

        verify(metadataSource, times(1)).reload();
    }

}