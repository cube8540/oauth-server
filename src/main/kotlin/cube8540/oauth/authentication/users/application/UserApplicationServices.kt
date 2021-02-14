package cube8540.oauth.authentication.users.application

import cube8540.oauth.authentication.users.domain.ApprovalAuthority

interface UserManagementService {
    fun countUser(username: String): Long

    fun loadUserProfile(username: String): UserProfile

    fun registerUser(registerRequest: UserRegisterRequest): CredentialsKeyUserProfile

    fun removeUser(username: String): UserProfile
}

interface UserPasswordService {
    fun changePassword(username: String, changeRequest: ChangePasswordRequest): UserProfile

    fun forgotPassword(username: String): ForgotUserPassword

    fun validateCredentialsKey(username: String, credentialsKey: String): Boolean

    fun resetPassword(resetRequest: ResetPasswordRequest): UserProfile
}

interface UserCredentialsService {
    fun grantCredentialsKey(username: String): CredentialsKeyUserProfile

    fun accountCredentials(username: String, credentialsKey: String): UserProfile
}

interface UserApprovalAuthorityService {
    fun getApprovalAuthorities(username: String): Collection<ApprovalAuthority>

    fun grantApprovalAuthorities(username: String, authorities: Collection<ApprovalAuthority>): UserProfile

    fun revokeApprovalAuthorities(username: String, authorities: Collection<ApprovalAuthority>): UserProfile
}