package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import lombok.Value;

import java.net.URI;

@Value
public class DefaultSecuredResourceDetails implements SecuredResourceDetails {

    private String resourceId;

    private URI resource;

    private ResourceMethod method;

    public static DefaultSecuredResourceDetails of(SecuredResource securedResource) {
        return new DefaultSecuredResourceDetails(securedResource.getResourceId().getValue(), securedResource.getResource(), securedResource.getMethod());
    }

}
