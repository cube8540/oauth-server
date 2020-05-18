package cube8540.oauth.authentication.credentials.resource.domain.converter;

import javax.persistence.AttributeConverter;
import java.net.URI;

public class ResourceConverter implements AttributeConverter<URI, String> {
    @Override
    public String convertToDatabaseColumn(URI attribute) {
        return attribute.toString();
    }

    @Override
    public URI convertToEntityAttribute(String dbData) {
        return URI.create(dbData);
    }
}
