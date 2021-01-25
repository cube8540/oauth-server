package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.Username
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.*

@Service
class DefaultUserService @Autowired constructor(
    private val repository: UserRepository
): UserDetailsService {

    @Transactional(readOnly = true)
    override fun loadUserByUsername(username: String): UserDetails {
        val user = repository.findById(Username(username))
            .orElseThrow { UsernameNotFoundException("$username is not found") }

        return User.builder()
            .username(user.username.value).password(user.password)
            .accountLocked(!user.credentialed)
            .authorities(Collections.emptyList())
            .build()
    }
}