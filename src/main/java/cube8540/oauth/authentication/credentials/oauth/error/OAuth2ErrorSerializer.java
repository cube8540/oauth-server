package cube8540.oauth.authentication.credentials.oauth.error;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.io.IOException;

public class OAuth2ErrorSerializer extends StdSerializer<OAuth2Error> {

    public OAuth2ErrorSerializer() {
        super(OAuth2Error.class);
    }

    @Override
    public void serialize(OAuth2Error value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeStartObject();
        gen.writeStringField(OAuth2Utils.ErrorMessageKey.ERROR, value.getErrorCode());
        gen.writeStringField(OAuth2Utils.ErrorMessageKey.DESCRIPTION, value.getDescription());
        gen.writeEndObject();
    }
}
