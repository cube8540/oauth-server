package cube8540.oauth.authentication.oauth.client.domain

import cube8540.validator.core.ValidationError
import cube8540.validator.core.ValidationRule
import cube8540.validator.core.Validator
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.*
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder

class OAuth2ClientTest {

    private val clientId = "clientId"
    private val clientSecret = "clientSecret"

    @Nested
    inner class EncryptingTest {

        private val client = OAuth2Client(clientId, clientSecret)

        @Test
        fun `encoding client secret`() {
            val encoder: PasswordEncoder = mockk()

            every { encoder.encode("clientSecret") } returns "encodedClientSecret"

            client.encrypted(encoder)
            assertThat(client.secret).isEqualTo("encodedClientSecret")
        }
    }

    @Nested
    inner class ValidationTest {

        private val validatorFactory: OAuth2ClientValidatorFactory = mockk()
        private val client = OAuth2Client(clientId, clientSecret)

        @Test
        fun `client data is invalid`() {
            val rule: ValidationRule<OAuth2Client> = mockk {
                every { isValid(client) } returns false
                every { error() } returns ValidationError("clientId", "test")
            }
            every { validatorFactory.createValidator(client) } returns Validator.of(client).registerRule(rule)

            val thrown = catchThrowable { client.validate(validatorFactory) }
            assertThat(thrown).isInstanceOf(ClientInvalidException::class.java)
        }

        @Test
        fun `client data is allowed`() {
            val rule: ValidationRule<OAuth2Client> = mockk {
                every { isValid(client) } returns true
            }
            every { validatorFactory.createValidator(client) } returns Validator.of(client).registerRule(rule)

            assertThatCode { client.validate(validatorFactory) }.doesNotThrowAnyException()
        }
    }

    @Nested
    inner class SecretChangeTest {

        private val client = OAuth2Client(clientId, clientSecret)

        @Test
        fun `existing secret is not equal`() {
            val encoder: PasswordEncoder = mockk {
                every { matches("existingSecret", clientSecret) } returns false
            }

            val thrown = catchThrowable { client.changeSecret("existingSecret", "newSecret", encoder) }
            assertThat(thrown).isInstanceOf(ClientAuthorizationException::class.java)
            assertThat((thrown as ClientAuthorizationException).code).isEqualTo(ClientErrorCodes.INVALID_PASSWORD)
        }

        @Test
        fun `change secret successful`() {
            val encoder: PasswordEncoder = mockk {
                every { matches("existingSecret", clientSecret) } returns true
            }

            client.changeSecret("existingSecret", "newSecret", encoder)
            assertThat(client.secret).isEqualTo("newSecret")
        }
    }
}