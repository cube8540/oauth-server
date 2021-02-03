package cube8540.oauth.authentication.users.domain

import cube8540.validator.core.Validator

interface UserCredentialsKeyGenerator {
    fun generateKey(): UserCredentialsKey
}

interface UserUidGenerator {
    fun generateUid(): Uid
}

interface UserValidatorFactory {
    fun createValidator(user: User): Validator<User>
}