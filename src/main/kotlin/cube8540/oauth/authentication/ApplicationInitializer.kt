package cube8540.oauth.authentication

import org.springframework.core.env.Environment

interface ApplicationInitializer {
    fun initialize(environment: Environment)
}