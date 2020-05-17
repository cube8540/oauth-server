package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import cube8540.oauth.authentication.credentials.oauth.scope.domain.OAuth2ScopeId;
import lombok.Value;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Value
public class DefaultSecuredResourceDetails implements SecuredResourceDetails {

    private String resourceId;

    private URI resource;

    private ResourceMethod method;

    private List<String> authorities;

    public static DefaultSecuredResourceDetails of(SecuredResource securedResource) {
        List<String> authorities = Optional.ofNullable(securedResource.getAuthorities()).orElse(Collections.emptySet())
                .stream().map(OAuth2ScopeId::getValue).collect(Collectors.toList());
        return new DefaultSecuredResourceDetails(securedResource.getResourceId().getValue(), securedResource.getResource(), securedResource.getMethod(), authorities);
    }

}
