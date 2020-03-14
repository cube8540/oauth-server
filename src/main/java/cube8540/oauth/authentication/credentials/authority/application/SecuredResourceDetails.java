package cube8540.oauth.authentication.credentials.authority.application;

import cube8540.oauth.authentication.credentials.authority.domain.ResourceMethod;

import java.net.URI;

public interface SecuredResourceDetails {

    String getResourceId();

    URI getResource();

    ResourceMethod getMethod();

}
