package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.users.application.DefaultUserService
import cube8540.oauth.authentication.users.domain.Uid
import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.Username
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.junit.jupiter.api.Test
import org.springframework.security.core.userdetails.UsernameNotFoundException
import java.util.*

class DefaultUserServiceTest {

    private val userRepository: UserRepository = mockk()
    private val service: DefaultUserService = DefaultUserService(userRepository)

    @Test
    fun `loading not registered user`() {
        every { userRepository.findById(Username("username")) } returns Optional.empty()

        val thrown = catchThrowable { service.loadUserByUsername("username") }
        assertThat(thrown).isInstanceOf(UsernameNotFoundException::class.java)
    }

    @Test
    fun `loaded user is not certified`() {
        val user: User = mockk {
            every { uid } returns Uid("uid")
            every { username } returns Username("username")
            every { password } returns "password"
            every { credentialed } returns false
        }

        every { userRepository.findById(Username("username")) } returns Optional.of(user)

        val result = service.loadUserByUsername("username")
        assertThat(result.isAccountNonLocked).isFalse
    }

    @Test
    fun `loaded user is certified`() {
        val user: User = mockk {
            every { uid } returns Uid("uid")
            every { username } returns Username("username")
            every { password } returns "password"
            every { credentialed } returns true
        }

        every { userRepository.findById(Username("username")) } returns Optional.of(user)

        val result = service.loadUserByUsername("username")
        assertThat(result.isAccountNonLocked).isTrue
        assertThat(result.authorities).isEmpty()
    }

}