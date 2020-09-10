package cube8540.oauth.authentication.credentials.resource.domain.exception;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.message.ErrorCodes;

public class ResourceRegisterException extends ServiceException {

    public ResourceRegisterException(String code, String description) {
        super(code, description);
    }

    public static ResourceRegisterException existsIdentifier(String description) {
        return new ResourceRegisterException(ErrorCodes.EXISTS_IDENTIFIER, description);
    }
}
