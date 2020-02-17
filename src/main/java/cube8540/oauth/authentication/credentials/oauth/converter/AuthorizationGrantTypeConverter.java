package cube8540.oauth.authentication.credentials.oauth.converter;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import javax.persistence.AttributeConverter;

public class AuthorizationGrantTypeConverter implements AttributeConverter<AuthorizationGrantType, String> {
    @Override
    public String convertToDatabaseColumn(AuthorizationGrantType attribute) {
        return attribute.getValue();
    }

    @Override
    public AuthorizationGrantType convertToEntityAttribute(String dbData) {
        return OAuth2Utils.extractGrantType(dbData);
    }
}
