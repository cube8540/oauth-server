package cube8540.oauth.authentication.credentials.authority.security;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;
import java.util.Map;

public interface SecurityMetadataLoadService {

    Map<RequestMatcher, Collection<ConfigAttribute>> loadSecurityMetadata();

}
