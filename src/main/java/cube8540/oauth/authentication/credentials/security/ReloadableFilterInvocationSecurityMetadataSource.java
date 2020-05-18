package cube8540.oauth.authentication.credentials.security;

import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

public interface ReloadableFilterInvocationSecurityMetadataSource extends FilterInvocationSecurityMetadataSource {

    void reload();

}
