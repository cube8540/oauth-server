package cube8540.oauth.authentication.credentials.resource.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class ResourceNotFoundException extends ServiceException {

    public ResourceNotFoundException(String code, String description) {
        super(code, description);
    }

    public static ResourceNotFoundException instance(String description) {
        return new ResourceNotFoundException(ErrorCodes.NOT_FOUND, description);
    }

}
