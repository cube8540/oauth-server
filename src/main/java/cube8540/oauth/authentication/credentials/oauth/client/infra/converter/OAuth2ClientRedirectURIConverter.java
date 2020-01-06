package cube8540.oauth.authentication.credentials.oauth.client.infra.converter;

import javax.persistence.AttributeConverter;
import java.net.URI;

public class OAuth2ClientRedirectURIConverter implements AttributeConverter<URI, String> {
    @Override
    public String convertToDatabaseColumn(URI attribute) {
        return attribute.toString();
    }

    @Override
    public URI convertToEntityAttribute(String dbData) {
        return URI.create(dbData);
    }
}
