package cube8540.oauth.authentication.users.application;

public interface UserManagementService {

    Long countUser(String email);

    UserProfile loadUserProfile(String email);

    UserProfile registerUser(UserRegisterRequest registerRequest);

    UserProfile removeUser(String email);

}
