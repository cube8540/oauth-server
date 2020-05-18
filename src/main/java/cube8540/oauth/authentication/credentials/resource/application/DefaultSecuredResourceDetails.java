package cube8540.oauth.authentication.credentials.resource.application;

import cube8540.oauth.authentication.credentials.resource.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.resource.domain.SecuredResource;
import lombok.Value;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Value
public class DefaultSecuredResourceDetails implements SecuredResourceDetails {

    String resourceId;

    URI resource;

    ResourceMethod method;

    List<AccessibleAuthorityValue> authorities;

    public static DefaultSecuredResourceDetails of(SecuredResource securedResource) {
        List<AccessibleAuthorityValue> authorities = Optional.ofNullable(securedResource.getAuthorities()).orElse(Collections.emptySet())
                .stream().map(AccessibleAuthorityValue::of).collect(Collectors.toList());
        return new DefaultSecuredResourceDetails(securedResource.getResourceId().getValue(), securedResource.getResource(),
                securedResource.getMethod(), authorities);
    }

}
