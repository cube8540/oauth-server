package cube8540.oauth.authentication.credentials.authority.application;

import java.util.List;

public interface SecuredResourceManagementService {

    Long count(String resourceId);

    List<SecuredResourceDetails> getResources();

    SecuredResourceDetails registerNewResource(SecuredResourceRegisterRequest registerRequest);

    SecuredResourceDetails modifyResource(String resourceId, SecuredResourceModifyRequest modifyRequest);

    SecuredResourceDetails removeResource(String resourceId);

}
