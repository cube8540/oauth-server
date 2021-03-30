package cube8540.oauth.authentication.user.application

import cube8540.oauth.authentication.users.application.UserInitializer
import cube8540.oauth.authentication.users.domain.User
import cube8540.oauth.authentication.users.domain.UserRepository
import cube8540.oauth.authentication.users.domain.Username
import io.mockk.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.core.env.Environment
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.*

class UserInitializerTest {

    private val initUsernameKey = "init-user.username"
    private val initPasswordKey = "init-user.password"

    private val userRepository: UserRepository = mockk()
    private val passwordEncoder: PasswordEncoder = mockk()
    private val environment: Environment = mockk()

    private val initializer: UserInitializer = UserInitializer(userRepository, passwordEncoder)

    @Test
    fun `target user is not registered in repository`() {
        val userCaptor = slot<User>()

        every { environment.getRequiredProperty(initUsernameKey) } returns "username"
        every { environment.getRequiredProperty(initPasswordKey) } returns "password"
        every { passwordEncoder.encode("password") } returns "encodedPassword"
        every { userRepository.findById(Username("username")) } returns Optional.empty()
        every { userRepository.save(capture(userCaptor)) } returnsArgument 0

        initializer.initialize(environment)
        assertThat(userCaptor.isCaptured).isTrue
        assertThat(userCaptor.captured.username).isEqualTo(Username("username"))
        assertThat(userCaptor.captured.password).isEqualTo("encodedPassword")
        assertThat(userCaptor.captured.credentialed).isTrue
    }

    @Test
    fun `target user is registered in repository`() {
        val user: User = mockk()

        every { environment.getRequiredProperty(initUsernameKey) } returns "username"
        every { environment.getRequiredProperty(initPasswordKey) } returns "password"
        every { userRepository.findById(Username("username")) } returns Optional.of(user)

        initializer.initialize(environment)
        verify { userRepository.save(any()) wasNot Called }
    }

}