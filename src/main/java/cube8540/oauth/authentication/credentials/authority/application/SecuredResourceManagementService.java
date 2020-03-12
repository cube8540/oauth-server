package cube8540.oauth.authentication.credentials.authority.application;

import java.util.List;

public interface SecuredResourceManagementService {

    List<SecuredResourceDetails> getResources();

    SecuredResourceDetails registerNewResource(SecuredResourceRegisterRequest registerRequest);

    SecuredResourceDetails modifyResource(String resourceId, SecuredResourceModifyRequest modifyRequest);

    SecuredResourceDetails removeResource(String resourceId);

}
