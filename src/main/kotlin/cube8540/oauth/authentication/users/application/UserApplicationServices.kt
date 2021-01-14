package cube8540.oauth.authentication.users.application

interface UserManagementService {
    fun countUser(username: String): Long

    fun loadUserProfile(username: String): UserProfile

    fun registerUser(registerRequest: UserRegisterRequest): RegisteredUserProfile

    fun removeUser(username: String): UserProfile
}

interface UserPasswordService {
    fun changePassword(username: String, changeRequest: ChangePasswordRequest): UserProfile

    fun forgotPassword(username: String): UserProfile

    fun validateCredentialsKey(username: String, credentialsKey: String): Boolean

    fun resetPassword(resetRequest: ResetPasswordRequest): UserProfile
}

interface UserCredentialsService {
    fun grantCredentialsKey(username: String): UserProfile

    fun accountCredentials(username: String, credentialsKey: String): UserProfile
}