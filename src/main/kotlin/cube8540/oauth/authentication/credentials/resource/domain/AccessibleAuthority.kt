package cube8540.oauth.authentication.credentials.resource.domain

import java.io.Serializable
import javax.persistence.Column
import javax.persistence.Embeddable

@Embeddable
data class AccessibleAuthority(var authority: String): Serializable