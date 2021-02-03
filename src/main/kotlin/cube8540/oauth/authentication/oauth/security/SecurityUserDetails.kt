package cube8540.oauth.authentication.oauth.security

import org.springframework.security.core.userdetails.UserDetails

interface SecurityUserDetails: UserDetails {

    val uid: String

}