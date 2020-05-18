package cube8540.oauth.authentication.credentials.security;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
@Component
public class UriSecurityMetadataSource implements ReloadableFilterInvocationSecurityMetadataSource {

    private final SecurityMetadataLoadService service;

    private Map<RequestMatcher, Collection<ConfigAttribute>> metadata;

    @Autowired
    public UriSecurityMetadataSource(SecurityMetadataLoadService service) {
        this.service = service;
        this.metadata = service.loadSecurityMetadata();
    }

    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        return metadata.entrySet().stream().filter(entry -> entry.getKey().matches(request))
                .map(Map.Entry::getValue).flatMap(Collection::stream).collect(Collectors.toSet());
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return metadata.values().stream().flatMap(Collection::stream).collect(Collectors.toSet());
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

    @Override
    public void reload() {
        this.metadata = service.loadSecurityMetadata();
    }
}
