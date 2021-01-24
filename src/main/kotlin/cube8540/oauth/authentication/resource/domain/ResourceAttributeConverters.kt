package cube8540.oauth.authentication.resource.domain

import java.net.URI
import javax.persistence.AttributeConverter

class ResourceConverter: AttributeConverter<URI, String> {
    override fun convertToDatabaseColumn(attribute: URI): String = attribute.toString()

    override fun convertToEntityAttribute(dbData: String): URI = URI.create(dbData)
}