package cube8540.oauth.authentication.resource.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class AccessibleAuthority(var authority: String): Serializable