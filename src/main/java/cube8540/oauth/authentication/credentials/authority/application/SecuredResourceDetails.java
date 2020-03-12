package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;
import cube8540.oauth.authentication.credentials.authority.domain.SecuredResource;
import lombok.Value;

import java.net.URI;

@Value
public class SecuredResourceDetails {

    private String resourceId;

    private URI resource;

    private ResourceMethod method;

    public static SecuredResourceDetails of(SecuredResource securedResource) {
        return new SecuredResourceDetails(securedResource.getResourceId().getValue(), securedResource.getResource(), securedResource.getMethod());
    }

}
