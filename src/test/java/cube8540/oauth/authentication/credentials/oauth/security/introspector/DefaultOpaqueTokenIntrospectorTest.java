package cube8540.oauth.authentication.credentials.oauth.security.introspector;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_PRINCIPAL_NAME;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_ROLE_AUTHORITY;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_SCOPE_AUTHORITY;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.RAW_TOKEN;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.ROLE_AUTHORITIES;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.mockOAuthAuthenticatedPrincipal;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.mockUser;
import static cube8540.oauth.authentication.credentials.oauth.security.introspector.OpaqueTokenIntrospectorTestSupport.mockUserDetailsService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("기본 토큰 인증 교환 클래스 테스트")
class DefaultOpaqueTokenIntrospectorTest {

    @Nested
    @DisplayName("교환")
    class introspect {

        @Nested
        @DisplayName("스코프가 null 일시")
        class WhenScopeIsNull {
            private DefaultOpaqueTokenIntrospector introspector;
            private Map<String, Object> attributes;

            @BeforeEach
            void setup() {
                this.attributes = new HashMap<>();
                OpaqueTokenIntrospector delegate = mock(OpaqueTokenIntrospector.class);
                OAuth2AuthenticatedPrincipal mockPrincipal = mockOAuthAuthenticatedPrincipal()
                        .configDefault()
                        .configUsernameInAttribute(RAW_PRINCIPAL_NAME)
                        .configAuthoritiesInAttribute(null)
                        .configAttributes(this.attributes)
                        .build();
                when(delegate.introspect(RAW_TOKEN)).thenReturn(mockPrincipal);

                User user = mockUser().configAuthorities(ROLE_AUTHORITIES).build();
                this.introspector = new DefaultOpaqueTokenIntrospector(delegate, mockUserDetailsService().registerUser(user).build());
                this.attributes.put(OAuth2IntrospectionClaimNames.USERNAME, RAW_PRINCIPAL_NAME);
                this.attributes.put(OAuth2IntrospectionClaimNames.SCOPE, RAW_SCOPE_AUTHORITY);
            }

            @Test
            @DisplayName("아이디는 검색된 인증 주체의 속성에서 가져온 아이디 이어야 한다.")
            void shouldPrincipalNameGetFromAuthenticationAttribute() {
                OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(RAW_TOKEN);

                assertEquals(RAW_PRINCIPAL_NAME, principal.getName());
            }

            @Test
            @DisplayName("속성은 검색된 인증 주처의 속성과 같아야 한다.")
            void shouldPrincipalAttributeIsEqualsToAuthenticationAttribute() {
                OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(RAW_TOKEN);

                assertEquals(this.attributes, principal.getAttributes());
            }

            @Test
            @DisplayName("권한은 검색해서 나온 유저의 권한만 가지고 있어야 한다.")
            void shouldAuthorityIsOnlySearchUsersAuthorities() {
                OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(RAW_TOKEN);

                assertEquals(ROLE_AUTHORITIES, new HashSet<GrantedAuthority>(principal.getAuthorities()));
            }
        }

        @Nested
        @DisplayName("스코프가 null이 아닐시")
        class WhenScopesIsNotNull {
            private DefaultOpaqueTokenIntrospector introspector;
            private Map<String, Object> attributes;

            @BeforeEach
            void setup() {
                this.attributes = new HashMap<>();
                OpaqueTokenIntrospector delegate = mock(OpaqueTokenIntrospector.class);
                OAuth2AuthenticatedPrincipal mockPrincipal = mockOAuthAuthenticatedPrincipal()
                        .configDefault()
                        .configUsernameInAttribute(RAW_PRINCIPAL_NAME)
                        .configAuthoritiesInAttribute(RAW_SCOPE_AUTHORITY)
                        .configAttributes(this.attributes)
                        .build();

                when(delegate.introspect(RAW_TOKEN)).thenReturn(mockPrincipal);

                User user = mockUser().configAuthorities(ROLE_AUTHORITIES).build();
                this.introspector = new DefaultOpaqueTokenIntrospector(delegate, mockUserDetailsService().registerUser(user).build());
                this.attributes.put(OAuth2IntrospectionClaimNames.USERNAME, RAW_PRINCIPAL_NAME);
                this.attributes.put(OAuth2IntrospectionClaimNames.SCOPE, RAW_SCOPE_AUTHORITY);
            }

            @Test
            @DisplayName("아이디는 검색된 인증 주체의 속성에서 가져온 아이디 이어야 한다.")
            void shouldPrincipalNameGetFromAuthenticationAttribute() {
                OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(RAW_TOKEN);

                assertEquals(RAW_PRINCIPAL_NAME, principal.getName());
            }

            @Test
            @DisplayName("속성은 검색된 인증 주체의 속성과 같아야 한다.")
            void shouldPrincipalAttributeIsEqualsToAuthenticationAttribute() {
                OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(RAW_TOKEN);

                assertEquals(this.attributes, principal.getAttributes());
            }

            @Test
            @DisplayName("스코프는 검색된 인증 주체의 속성에서 가져온 스코프와 검색된 유저의 권한을 합친 권한 이어야 한다.")
            void shouldScopeGetFromAuthenticationAttribute() {
                OAuth2AuthenticatedPrincipal principal = this.introspector.introspect(RAW_TOKEN);

                Collection<GrantedAuthority> expected = Stream.concat(
                        RAW_SCOPE_AUTHORITY.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()).stream(),
                        RAW_ROLE_AUTHORITY.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()).stream())
                        .collect(Collectors.toSet());
                assertEquals(expected, new HashSet<>(principal.getAuthorities()));
            }
        }
    }
}