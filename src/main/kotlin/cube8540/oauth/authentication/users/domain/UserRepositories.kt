package cube8540.oauth.authentication.users.domain

import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository: JpaRepository<User, Username> {
    fun countByUsername(username: Username): Long
}