package cube8540.oauth.authentication.user.domain

import cube8540.oauth.authentication.users.domain.*
import cube8540.validator.core.ValidationError
import cube8540.validator.core.ValidationRule
import cube8540.validator.core.Validator
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.security.crypto.password.PasswordEncoder

class UserTest {

    @Nested
    inner class ValidationTest {
        private val userValidatorFactory = mockk<UserValidatorFactory>()
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator>()
            every { uidGenerator.generateUid() } returns Uid("UID")

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `user data is invalid`() {
            val rule = mockk<ValidationRule<User>> {
                every { isValid(user) } returns false
                every { error() } returns ValidationError("username", "test")
            }
            every { userValidatorFactory.createValidator(user) } returns Validator.of(user).registerRule(rule)

            val thrown = catchThrowable { user.validation(userValidatorFactory) }
            assertThat(thrown).isInstanceOf(UserInvalidException::class.java)
        }

        @Test
        fun `user data is allowed`() {
            val rule = mockk<ValidationRule<User>> {
                every { isValid(user) } returns true
            }
            every { userValidatorFactory.createValidator(user) } returns Validator.of(user).registerRule(rule)

            assertThatCode { user.validation(userValidatorFactory) }.doesNotThrowAnyException()
        }
    }

    @Nested
    inner class EncryptingTest {
        private val user: User
        private val encoder = mockk<PasswordEncoder>()

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `password encrypting`() {
            every { encoder.encode("password") } returns "encodingPassword"

            user.encrypted(encoder)
            assertThat(user.password).isEqualTo("encodingPassword")
        }
    }

    @Nested
    inner class PasswordChangeTest {
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `existing password is not equal`() {
            val encoder = mockk<PasswordEncoder> {
                every { matches("existingPassword", "password") } returns false
            }

            val thrown = catchThrowable { user.changePassword("existingPassword", "newPassword", encoder) }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.INVALID_PASSWORD)
        }

        @Test
        fun `change password successful`() {
            val encoder = mockk<PasswordEncoder> {
                every { matches("existingPassword", "password") } returns true
            }

            user.changePassword("existingPassword", "newPassword", encoder)
            assertThat(user.password).isEqualTo("newPassword")
        }
    }

    @Nested
    inner class GenerateCredentialsKeyTest {
        private val credentialsKey = mockk<UserCredentialsKey>()
        private val generator = mockk<UserCredentialsKeyGenerator>()
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }
            every { generator.generateKey() } returns credentialsKey

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `generate credentials key for user`() {
            user.generateCredentialsKey(generator)

            assertThat(user.credentialsKey).isEqualTo(credentialsKey)
        }

        @Test
        fun `user account is already credentials`() {
            accountCredentials()

            val thrown = catchThrowable { user.generateCredentialsKey(generator) }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code)
                .isEqualTo(UserErrorCodes.ALREADY_CREDENTIALS)
        }

        private fun accountCredentials() {
            user.generateCredentialsKey(generator)
            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.MATCHED
            user.credentials("key")
        }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_METHOD)
    inner class CredentialsTest {
        private val credentialsKey = mockk<UserCredentialsKey>()
        private val generator = mockk<UserCredentialsKeyGenerator>()
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }
            every { generator.generateKey() } returns credentialsKey

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `credentials key is not generated`() {
            val thrown = catchThrowable { user.credentials("key") }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.INVALID_KEY)
        }

        @Test
        fun `credentials key is not matches`() {
            user.generateCredentialsKey(generator)

            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.NOT_MATCHED

            val thrown = catchThrowable { user.credentials("key") }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.INVALID_KEY)
        }

        @Test
        fun `credentials key is expired`() {
            user.generateCredentialsKey(generator)

            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.EXPIRED

            val thrown = catchThrowable { user.credentials("key") }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.KEY_EXPIRED)
        }

        @Test
        fun `credentials is successful`() {
            user.generateCredentialsKey(generator)

            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.MATCHED

            user.credentials("key")
            assertThat(user.credentialed).isTrue
            assertThat(user.credentialsKey).isNull()
        }
    }

    @Nested
    inner class ForgotPasswordTest {
        private val credentialsKey = mockk<UserCredentialsKey>()
        private val generator = mockk<UserCredentialsKeyGenerator>()
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }
            every { generator.generateKey() } returns credentialsKey

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `request forgot password`() {
            user.forgotPassword(generator)

            assertThat(user.passwordCredentialsKey).isEqualTo(credentialsKey)
        }
    }

    @Nested
    inner class ResetPasswordTest {
        private val credentialsKey = mockk<UserCredentialsKey>()
        private val generator = mockk<UserCredentialsKeyGenerator>()
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }
            every { generator.generateKey() } returns credentialsKey

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `password credentials key is not generated`() {
            val thrown = catchThrowable { user.resetPassword("key", "newPassword") }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.INVALID_KEY)
        }

        @Test
        fun `password credentials key is not matches`() {
            user.forgotPassword(generator)

            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.NOT_MATCHED

            val thrown = catchThrowable { user.resetPassword("key", "newPassword") }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.INVALID_KEY)
        }

        @Test
        fun `password credentials key is expired`() {
            user.forgotPassword(generator)

            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.EXPIRED

            val thrown = catchThrowable { user.resetPassword("key", "newPassword") }
            assertThat(thrown).isInstanceOf(UserAuthorizationException::class.java)
            assertThat((thrown as UserAuthorizationException).code).isEqualTo(UserErrorCodes.KEY_EXPIRED)
        }

        @Test
        fun `reset password successful`() {
            user.forgotPassword(generator)

            every { credentialsKey.matches("key") } returns UserKeyMatchedResult.MATCHED

            user.resetPassword("key", "newPassword")
            assertThat(user.password).isEqualTo("newPassword")
            assertThat(user.passwordCredentialsKey).isNull()
        }
    }

    @Nested
    inner class AddApprovalAuthorityTest {
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `add approval successful`() {
            user.addApprovalAuthority("clientId", "approval")

            val expected = ApprovalAuthority("clientId", "approval")
            assertThat(user.approvalAuthorities).containsExactly(expected)
        }
    }

    @Nested
    inner class RevokeApprovalAuthorityTest {
        private val user: User

        init {
            val uidGenerator = mockk<UserUidGenerator> {
                every { generateUid() } returns Uid("UID")
            }

            this.user = User(uidGenerator, "username", "password")
        }

        @Test
        fun `revoke when approval authorities is null`() {
            assertThatCode { user.revokeApprovalAuthority("clientId", "approval") }
                .doesNotThrowAnyException()
        }

        @Test
        fun `revoke authority is successful`() {
            user.addApprovalAuthority("clientId", "approval")

            user.revokeApprovalAuthority("clientId", "approval")

            val expected = ApprovalAuthority("clientId", "approval")
            assertThat(user.approvalAuthorities).doesNotContain(expected)
        }
    }
}