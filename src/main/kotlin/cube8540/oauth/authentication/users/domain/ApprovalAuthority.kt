package cube8540.oauth.authentication.users.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class ApprovalAuthority(
    var clientId: String,

    var scopeId: String
): Serializable