package cube8540.oauth.authentication.users.domain;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static cube8540.oauth.authentication.users.domain.UserTestHelper.APPROVAL_AUTHORITY;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.AUTHORITY;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.CHANGE_PASSWORD;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.CLIENT_ID;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.ENCRYPTED_PASSWORD;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.PASSWORD;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.RAW_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.RAW_PASSWORD_CREDENTIALS_KEY;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.RAW_USERNAME;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.UID;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeCredentialsKey;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeErrorValidatorFactory;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeExpiredKey;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeKeyGenerator;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeMismatchedKey;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeMismatchesEncoder;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makePassValidatorFactory;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makePasswordEncoder;
import static cube8540.oauth.authentication.users.domain.UserTestHelper.makeUidGenerator;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("유저 계정 테스트")
class UserTest {

    @Test
    @DisplayName("유효 하지 않은 정보가 저장 되어 있을시")
    void userDataInvalid() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserValidatorFactory factory = makeErrorValidatorFactory(user);

        assertThrows(UserInvalidException.class, () -> user.validation(factory));
    }

    @Test
    @DisplayName("모든 데이터가 유효할시")
    void userDataAllowed() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserValidatorFactory factory = makePassValidatorFactory(user);

        assertDoesNotThrow(() -> user.validation(factory));
    }

    @Test
    @DisplayName("패스워드 변경시 이전에 사용 하던 패스워드와 일치 하지 않을시")
    void changePasswordWhenNotMatchedExistingPassword() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);
        PasswordEncoder encoder = makeMismatchesEncoder(PASSWORD, ENCRYPTED_PASSWORD);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.changePassword(PASSWORD, CHANGE_PASSWORD, encoder));
        Assertions.assertEquals(UserErrorCodes.INVALID_PASSWORD, e.getCode());
    }

    @Test
    @DisplayName("패스워드 변경")
    void changePassword() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCRYPTED_PASSWORD);

        user.encrypted(encoder);

        user.changePassword(PASSWORD, CHANGE_PASSWORD, encoder);
        assertEquals(CHANGE_PASSWORD, user.getPassword());
    }

    @Test
    @DisplayName("패스워드 분실")
    void forgotPassword() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);
        UserCredentialsKey key = makeCredentialsKey(RAW_PASSWORD_CREDENTIALS_KEY);
        UserCredentialsKeyGenerator generator = makeKeyGenerator(key);

        user.forgotPassword(generator);

        assertEquals(key, user.getPasswordCredentialsKey());
    }

    @Test
    @DisplayName("패스워드 인증키가 할당 되지 않은 계정의 패스워드 초기화")
    void resetPasswordToNotGeneratedCredentialsKeyUser() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.resetPassword(RAW_PASSWORD_CREDENTIALS_KEY, CHANGE_PASSWORD));
        assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
    }

    @Test
    @DisplayName("패스워드 인증키가 매칭 되지 않은 계정의 패스워드 초기화")
    void resetPasswordKeyIsNotMatched() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKey key = makeMismatchedKey();
        UserCredentialsKeyGenerator generator = makeKeyGenerator(key);
        user.forgotPassword(generator);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.resetPassword(RAW_PASSWORD_CREDENTIALS_KEY, CHANGE_PASSWORD));
        assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
    }

    @Test
    @DisplayName("패스워드 인증키가 만료된 계정의 패스워드 초기화")
    void resetPasswordKeyIsExpired() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKey key = makeExpiredKey();
        UserCredentialsKeyGenerator generator = makeKeyGenerator(key);
        user.forgotPassword(generator);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.resetPassword(RAW_PASSWORD_CREDENTIALS_KEY, CHANGE_PASSWORD));
        assertEquals(UserErrorCodes.KEY_EXPIRED, e.getCode());
    }

    @Test
    @DisplayName("패스워드 초기화")
    void resetPassword() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKey key = makeCredentialsKey(RAW_CREDENTIALS_KEY);
        UserCredentialsKeyGenerator generator = makeKeyGenerator(key);
        user.forgotPassword(generator);

        user.resetPassword(RAW_CREDENTIALS_KEY, CHANGE_PASSWORD);
        assertEquals(CHANGE_PASSWORD, user.getPassword());
        assertNull(user.getPasswordCredentialsKey());
    }

    @Test
    @DisplayName("인증키 할당")
    void grantedCredentialsKey() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKey key = makeCredentialsKey(RAW_CREDENTIALS_KEY);
        UserCredentialsKeyGenerator generator = makeKeyGenerator(key);

        user.generateCredentialsKey(generator);
        assertEquals(key, user.getCredentialsKey());
    }

    @Test
    @DisplayName("이미 인증 받은 계정에 인증키 할당")
    void grantedCredentialsKeyToAlreadyCredentialsUser() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKey key = makeCredentialsKey(RAW_CREDENTIALS_KEY);
        UserCredentialsKeyGenerator generator = makeKeyGenerator(key);
        user.generateCredentialsKey(generator);
        user.credentials(RAW_CREDENTIALS_KEY);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.generateCredentialsKey(generator));
        assertEquals(UserErrorCodes.ALREADY_CREDENTIALS, e.getCode());
    }

    @Test
    @DisplayName("인증키가 할당 되지 않은 유저 계정 인증")
    void accountAuthenticationToNotGeneratedKeyUser() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.credentials(RAW_CREDENTIALS_KEY));
        assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
    }

    @Test
    @DisplayName("인증키가 매칭 되지 않은 계정 인증")
    void accountAuthenticationKeyIsNotMatched() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKeyGenerator generator = makeKeyGenerator(makeMismatchedKey());
        user.generateCredentialsKey(generator);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.credentials(RAW_CREDENTIALS_KEY));
        assertEquals(UserErrorCodes.INVALID_KEY, e.getCode());
    }

    @Test
    @DisplayName("인증키가 만료된 계정 인증")
    void accountAuthenticationKeyIsExpired() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKeyGenerator generator = makeKeyGenerator(makeExpiredKey());
        user.generateCredentialsKey(generator);

        UserAuthorizationException e = assertThrows(UserAuthorizationException.class, () -> user.credentials(RAW_CREDENTIALS_KEY));
        assertEquals(UserErrorCodes.KEY_EXPIRED, e.getCode());
    }

    @Test
    @DisplayName("계정 인증")
    void accountAuthentication() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        UserCredentialsKeyGenerator generator = makeKeyGenerator(makeCredentialsKey(RAW_CREDENTIALS_KEY));
        user.generateCredentialsKey(generator);

        user.credentials(RAW_CREDENTIALS_KEY);
        assertNull(user.getCredentialsKey());
        assertTrue(user.getCredentialed());
    }

    @Test
    @DisplayName("패스워드 암호화")
    void passwordEncrypting() {
        PasswordEncoder encoder = makePasswordEncoder(PASSWORD, ENCRYPTED_PASSWORD);
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        user.encrypted(encoder);
        assertEquals(ENCRYPTED_PASSWORD, user.getPassword());
    }

    @Test
    @DisplayName("유저 승인 권한 추가")
    void addApprovalAuthority() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        user.addApprovalAuthority(CLIENT_ID, AUTHORITY);
        assertTrue(user.getApprovalAuthorities().contains(APPROVAL_AUTHORITY));
    }

    @Test
    @DisplayName("유저 승인 권한이 null 일때 승인 권한 삭제")
    void revokeApprovalAuthorityWhenUserApprovalAuthoritiesIsNull() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        user.setApprovalAuthorities(null);

        assertDoesNotThrow(() -> user.revokeApprovalAuthority(CLIENT_ID, AUTHORITY));
    }

    @Test
    @DisplayName("유저 승인 권한 삭제")
    void revokeApprovalAuthority() {
        User user = new User(makeUidGenerator(UID), RAW_USERNAME, PASSWORD);

        user.addApprovalAuthority(CLIENT_ID, AUTHORITY);
        user.revokeApprovalAuthority(CLIENT_ID, AUTHORITY);

        assertFalse(user.getApprovalAuthorities().contains(APPROVAL_AUTHORITY));
    }
}