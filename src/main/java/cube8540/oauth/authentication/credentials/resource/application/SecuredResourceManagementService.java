package cube8540.oauth.authentication.credentials.resource.application;

public interface SecuredResourceManagementService extends SecuredResourceReadService {

    SecuredResourceDetails registerNewResource(SecuredResourceRegisterRequest registerRequest);

    SecuredResourceDetails modifyResource(String resourceId, SecuredResourceModifyRequest modifyRequest);

    SecuredResourceDetails removeResource(String resourceId);

}
