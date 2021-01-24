package cube8540.oauth.authentication.credentials.oauth.client.domain

import cube8540.validator.core.Validator

interface OAuth2ClientValidatorFactory {
    fun createValidator(client: OAuth2Client): Validator<OAuth2Client>
}