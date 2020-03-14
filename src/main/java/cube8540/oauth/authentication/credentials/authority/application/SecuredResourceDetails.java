package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;

import java.net.URI;
import java.util.List;

public interface SecuredResourceDetails {

    String getResourceId();

    URI getResource();

    ResourceMethod getMethod();

    List<String> getAuthorities();

}
