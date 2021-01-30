package cube8540.oauth.authentication.rememberme.domain

import org.springframework.data.jpa.repository.JpaRepository

interface RememberMeTokenRepository: JpaRepository<RememberMeToken, RememberMeTokenSeries>