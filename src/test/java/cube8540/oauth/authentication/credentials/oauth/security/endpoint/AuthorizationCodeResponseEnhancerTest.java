package cube8540.oauth.authentication.credentials.oauth.security.endpoint;

import cube8540.oauth.authentication.credentials.oauth.OAuth2Utils;
import cube8540.oauth.authentication.credentials.oauth.security.AuthorizationRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2AuthorizationCodeGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.web.servlet.ModelAndView;

import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.RAW_AUTHORIZATION_CODE;
import static cube8540.oauth.authentication.credentials.oauth.security.endpoint.AuthorizationEndpointTestHelper.STATE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("인가 코드 응답 메시지 추가 정보 입력 클래스 테스트")
class AuthorizationCodeResponseEnhancerTest {

    @Nested
    @DisplayName("ModelAndView 추가 정보 설정")
    class EnhanceModelAndView {

        @Nested
        @DisplayName("응답 타입이 인가 코드가 아닐시")
        class WhenResponseTypeIsNotAuthorizationCode extends AssertSetup {

            private AuthorizationRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                        .configDefault()
                        .configResponseType(OAuth2AuthorizationResponseType.TOKEN)
                        .build();
            }

            @Test
            @DisplayName("인가 토큰을 생성 하지 않아야 한다.")
            void shouldNotCreateAuthorizationCode() {
                enhancer.enhance(modelAndView, request);

                verify(generator, never()).generateNewAuthorizationCode(any());
            }

        }

        @Nested
        @DisplayName("response_type 이 authorization_code 일시")
        class WhenResponseTypeIsAuthorizationCode extends AssertSetup {

            private AuthorizationRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                        .configDefault()
                        .configResponseType(OAuth2AuthorizationResponseType.CODE)
                        .build();
            }

            @Test
            @DisplayName("입력 받은 인가 요청 정보로 인가 코드를 생성 해야 한다.")
            void shouldCreatedAuthorizationCodeByInputRequest() {
                enhancer.enhance(modelAndView, request);

                verify(generator, times(1)).generateNewAuthorizationCode(request);
            }

            @Test
            @DisplayName("생성한 인가 코드를 ModelAndView 에 저장 해야 한다.")
            void shouldSaveCreatedAuthorizationCodeInModelAndView() {
                enhancer.enhance(modelAndView, request);

                verify(modelAndView, times(1)).addObject(OAuth2Utils.AuthorizationResponseKey.CODE, RAW_AUTHORIZATION_CODE);
            }

            @Nested
            @DisplayName("입력 받은 인가 요청 정보에 state 정보가 없을시")
            class WhenAuthorizationRequestNotHasState extends AssertSetup {

                private AuthorizationRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                            .configDefault()
                            .configResponseType(OAuth2AuthorizationResponseType.CODE)
                            .configNullState()
                            .build();
                }

                @Test
                @DisplayName("ModelAndView 에 state 정보를 저장 하지 않아야 한다.")
                void shouldNotSaveStateInModelAndView() {
                    enhancer.enhance(modelAndView, request);

                    verify(modelAndView, never()).addObject(eq(OAuth2Utils.AuthorizationResponseKey.STATE), anyString());
                    verify(modelAndView, never()).addObject(OAuth2Utils.AuthorizationResponseKey.STATE, null);
                }
            }

            @Nested
            @DisplayName("입력 받은 인가 요청 정보에 state 정보가 있을시")
            class WhenAuthorizationRequestHasState extends AssertSetup {

                private AuthorizationRequest request;

                @BeforeEach
                void setupRequest() {
                    this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest()
                            .configDefault()
                            .configResponseType(OAuth2AuthorizationResponseType.CODE)
                            .configState()
                            .build();
                }

                @Test
                @DisplayName("ModelAndView 에 state 정보를 저장 해야 한다.")
                void shouldSaveStateInModelAndView() {
                    enhancer.enhance(modelAndView, request);

                    verify(modelAndView, times(1)).addObject(OAuth2Utils.AuthorizationResponseKey.STATE, STATE);
                }

            }
        }

        @Nested
        @DisplayName("다음 추가 입력 정보 클래스가 있을시")
        class WhenHasNextEnhancer extends AssertSetup {

            private AuthorizationRequest request;

            private ModelAndView nextModelAndView;
            private AuthorizationResponseEnhancer nextEnhancer;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest().configResponseType(OAuth2AuthorizationResponseType.CODE).configDefault().build();
            }

            @Override
            protected void configEnhancer(AuthorizationCodeResponseEnhancer handler) {
                this.nextEnhancer = mock(AuthorizationResponseEnhancer.class);
                this.nextModelAndView = mock(ModelAndView.class);

                when(nextEnhancer.enhance(any(), any())).thenReturn(nextModelAndView);
                handler.setNext(nextEnhancer);
            }

            @Test
            @DisplayName("다음 추가 입력 클래스에서 반환된 ModelAndView 를 반환 해야 한다.")
            void shouldReturnNextEnhancerModelAndView() {
                ModelAndView mv = enhancer.enhance(modelAndView, request);
                assertEquals(nextModelAndView, mv);
            }
        }

        @Nested
        @DisplayName("다음 추가 입력 정보 클래스가 없을시")
        class WhenHasNotNextEnhancer extends AssertSetup {

            private AuthorizationRequest request;

            @BeforeEach
            void setupRequest() {
                this.request = AuthorizationEndpointTestHelper.mockAuthorizationRequest().configResponseType(OAuth2AuthorizationResponseType.CODE).configDefault().build();
            }

            @Test
            @DisplayName("입력 받은 ModelAndView 를 반환 해야 한다.")
            void shouldReturnsInputModelAndView() {
                ModelAndView mv = enhancer.enhance(modelAndView, request);
                assertEquals(modelAndView, mv);
            }
        }
    }

    private static abstract class AssertSetup {
        protected OAuth2AuthorizationCodeGenerator generator;
        protected AuthorizationCodeResponseEnhancer enhancer;

        protected ModelAndView modelAndView;
        protected AuthorizationRequest request;
        protected String redirectUri;

        @BeforeEach
        void setup() {
            this.generator = AuthorizationEndpointTestHelper.mockCodeGenerator().configGenerated().build();
            this.enhancer = new AuthorizationCodeResponseEnhancer(generator);

            this.modelAndView = mock(ModelAndView.class);
            this.redirectUri = AuthorizationEndpointTestHelper.RAW_REDIRECT_URI;

            configEnhancer(enhancer);
        }

        protected void configEnhancer(AuthorizationCodeResponseEnhancer handler) {}
    }

}