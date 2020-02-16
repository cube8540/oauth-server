package cube8540.oauth.authentication.credentials.authority.endpoint;

import cube8540.oauth.authentication.credentials.authority.AuthorityDetails;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityManagementService;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityModifyRequest;
import cube8540.oauth.authentication.credentials.authority.application.AuthorityRegisterRequest;
import cube8540.oauth.authentication.message.ResponseMessage;
import cube8540.oauth.authentication.message.SuccessResponseMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("권한 관리 API 엔드 포인트 테스트")
class AuthorityManagementAPIEndpointTest {

    private static final String RAW_CODE = "CODE";

    private AuthorityManagementService service;
    private AuthorityManagementAPIEndpoint endpoint;

    @BeforeEach
    void setup() {
        this.service = mock(AuthorityManagementService.class);
        this.endpoint = new AuthorityManagementAPIEndpoint(service);
    }

    @Nested
    @DisplayName("권한 코드 카운팅 API")
    class AuthorityCodeCountAPI {
        private long randomCount;

        @BeforeEach
        void setup() {
            this.randomCount = (long) (Math.random() * 100);

            when(service.countAuthority(RAW_CODE)).thenReturn(randomCount);
        }

        @Test
        @DisplayName("요청 받은 이메일의 카운팅을 해야 한다.")
        void shouldCountingRequestingCode() {
            endpoint.countingAuthorityCode(RAW_CODE);

            verify(service, times(1)).countAuthority(RAW_CODE);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.countingAuthorityCode(RAW_CODE);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에 권한 코드의 갯수가 포함 되어야 한다.")
        void shouldResponseBodyContainsAuthorityCode() {
            ResponseEntity<ResponseMessage> response = endpoint.countingAuthorityCode(RAW_CODE);

            assertNotNull(response.getBody());
            assertEquals(randomCount, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

    @Nested
    @DisplayName("권한 정보 검색")
    class GetAuthorityDetails {
        private AuthorityDetails authority;

        @BeforeEach
        void setup() {
            this.authority = mock(AuthorityDetails.class);

            when(service.getAuthority(RAW_CODE)).thenReturn(authority);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.getAuthorityDetails(RAW_CODE);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에 요청 받은 권한의 정보가 포함되어야 한다.")
        void shouldResponseBodyContainsAuthorityDetails() {
            ResponseEntity<ResponseMessage> response = endpoint.getAuthorityDetails(RAW_CODE);

            assertNotNull(response.getBody());
            assertEquals(authority, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

    @Nested
    @DisplayName("권한 리스트 검색")
    class GetAuthorities {
        private List<AuthorityDetails> authorityDetails;

        @BeforeEach
        void setup() {
            this.authorityDetails = Arrays.asList(mocking(), mocking(), mocking());

            when(service.getAuthorities()).thenReturn(authorityDetails);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusCodeIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.getAuthorities();

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에 모든 권한의 정보가 담겨야 한다.")
        void shouldResponseBodyContainsAllAuthorityDetails() {
            ResponseEntity<ResponseMessage> response = endpoint.getAuthorities();

            assertNotNull(response.getBody());
            assertEquals(authorityDetails, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }

        private AuthorityDetails mocking() {
            return mock(AuthorityDetails.class);
        }
    }

    @Nested
    @DisplayName("권한 생성")
    class RegisterAuthority {
        private AuthorityRegisterRequest request;
        private AuthorityDetails authority;

        @BeforeEach
        void setup() {
            this.request = new AuthorityRegisterRequest(RAW_CODE, "", false);
            this.authority = mock(AuthorityDetails.class);

            when(service.registerAuthority(request)).thenReturn(authority);
        }

        @Test
        @DisplayName("요청 받은 정보로 권한을 등록해야 한다.")
        void shouldRegisterRequestingAuthority() {
            endpoint.registerAuthority(request);

            verify(service, times(1)).registerAuthority(request);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 201 이어야 한다")
        void shouldHttpStatusCodeIs201() {
            ResponseEntity<ResponseMessage> response = endpoint.registerAuthority(request);

            assertEquals(HttpStatus.CREATED, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에 새로 생성된 권한 정보가 담겨 있어야 한다.")
        void shouldResponseContainsRegisterAuthorityDetails() {
            ResponseEntity<ResponseMessage> response = endpoint.registerAuthority(request);

            assertNotNull(response.getBody());
            assertEquals(authority, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

    @Nested
    @DisplayName("권한 수정")
    class ModifyAuthority {
        private AuthorityModifyRequest request;
        private AuthorityDetails authority;

        @BeforeEach
        void setup() {
            this.request = new AuthorityModifyRequest("", false);
            this.authority = mock(AuthorityDetails.class);

            when(service.modifyAuthority(RAW_CODE, request)).thenReturn(authority);
        }

        @Test
        @DisplayName("요청 받은 권한 정보를 수정해야 한다.")
        void shouldModifyRequestingAuthority() {
            endpoint.modifyAuthority(RAW_CODE, request);

            verify(service, times(1)).modifyAuthority(RAW_CODE, request);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.modifyAuthority(RAW_CODE, request);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에 수정된 권한 정보가 담겨 있어야 한다.")
        void shouldResponseContainsModifyAuthorityDetails() {
            ResponseEntity<ResponseMessage> response = endpoint.modifyAuthority(RAW_CODE, request);

            assertNotNull(response.getBody());
            assertEquals(authority, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }

    @Nested
    @DisplayName("권한 삭제")
    class RemoveAuthority {
        private AuthorityDetails authority;

        @BeforeEach
        void setup() {
            this.authority = mock(AuthorityDetails.class);

            when(service.removeAuthority(RAW_CODE)).thenReturn(authority);
        }

        @Test
        @DisplayName("요청 받은 권한을 삭제해야 한다.")
        void shouldRemoveRequestingAuthority() {
            endpoint.removeAuthority(RAW_CODE);

            verify(service, times(1)).removeAuthority(RAW_CODE);
        }

        @Test
        @DisplayName("HTTP 상태 코드는 200 이어야 한다.")
        void shouldHttpStatusIs200() {
            ResponseEntity<ResponseMessage> response = endpoint.removeAuthority(RAW_CODE);

            assertEquals(HttpStatus.OK, response.getStatusCode());
        }

        @Test
        @DisplayName("응답 바디에 삭제된 권한 정보가 담겨 있어야 한다.")
        void shouldResponseContainsRemoveAuthorityDetails() {
            ResponseEntity<ResponseMessage> response = endpoint.removeAuthority(RAW_CODE);

            assertNotNull(response.getBody());
            assertEquals(authority, ((SuccessResponseMessage<?>) response.getBody()).getData());
        }
    }
}