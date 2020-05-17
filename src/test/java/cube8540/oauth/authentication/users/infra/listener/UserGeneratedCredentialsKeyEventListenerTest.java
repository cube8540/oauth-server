package cube8540.oauth.authentication.users.infra.listener;

import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserGeneratedCredentialsKeyEvent;
import cube8540.oauth.authentication.users.domain.Username;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.internet.MimeMessage;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("유저 인증키 할당 이벤트 리스너 클래스 테스트")
class UserGeneratedCredentialsKeyEventListenerTest {

    private static final String RAW_USERNAME = "username1234";
    private static final Username USERNAME = new Username(RAW_USERNAME);

    private static final String RAW_USER_EMAIL = "email@email.com";
    private static final UserEmail EMAIL = new UserEmail(RAW_USER_EMAIL);

    private static final String RAW_KEY = "TEST";
    private static final UserCredentialsKey KEY = new UserCredentialsKey(RAW_KEY);

    private static final String EMAIL_TEMPLATE = "TEST";

    private static final UserGeneratedCredentialsKeyEvent EVENT = new UserGeneratedCredentialsKeyEvent(USERNAME, EMAIL, KEY);

    @Nested
    @DisplayName("이메일 발송")
    class SendEmail {

        @Nested
        @DisplayName("JavaMailSender 인터페이스가 null 일시")
        class WhenJavaMailSenderIsNull {
            private UserGeneratedCredentialsKeyEventListener listener;

            @BeforeEach
            void setup() {
                this.listener = new UserGeneratedCredentialsKeyEventListener();
            }

            @Test
            @DisplayName("이벤트 발생히 아무 행동도 하지 않아야 한다.")
            void doNothing() {
                assertDoesNotThrow(() -> listener.sendCredentialsKeyEmail(EVENT));
            }
        }

        @Nested
        @DisplayName("JavaMailSender 인터페이스가 null 이 아닐시")
        class WhenJavaMailSenderIsNotNull {
            private JavaMailSender sender;
            private UserGeneratedCredentialsKeyEventListener listener;

            @BeforeEach
            void setup() {
                this.sender = mock(JavaMailSender.class);
                this.listener = new UserGeneratedCredentialsKeyEventListener(sender, mock(ITemplateEngine.class));
            }

            @Test
            @DisplayName("이메일을 발송해야 한다.")
            void shouldSendEmail() {
                listener.sendCredentialsKeyEmail(EVENT);

                verify(sender, times(1)).send(any(MimeMessagePreparator.class));
            }
        }
    }

    @Nested
    @DisplayName("이메일 메시지 생성")
    class CreateEmailMessage {
        private UserGeneratedCredentialsKeyEventListener listener;
        private ITemplateEngine engine;

        @BeforeEach
        void setup() {
            this.engine = mock(ITemplateEngine.class);
            this.listener = new UserGeneratedCredentialsKeyEventListener(mock(JavaMailSender.class), engine);

            when(engine.process(anyString(), any())).thenReturn(EMAIL_TEMPLATE);
        }

        @Test
        @DisplayName("제목을 설정해야 한다.")
        void shouldSetSubject() throws Exception {
            MimeMessage mimeMessage = mock(MimeMessage.class);

            MimeMessagePreparator preparator = listener.createMessage(EVENT);
            preparator.prepare(mimeMessage);

            verify(mimeMessage, times(1)).setSubject("가입 확인 이메일 입니다.");
        }

        @Test
        @DisplayName("수신자는 이벤트에 저장된 이메일 이어야 한다.")
        void shouldToIsRegisteredInEventsEmail() throws Exception {
            ArgumentCaptor<Address> addressCaptor = ArgumentCaptor.forClass(Address.class);
            MimeMessage mimeMessage = mock(MimeMessage.class);

            MimeMessagePreparator preparator = listener.createMessage(EVENT);
            preparator.prepare(mimeMessage);

            verify(mimeMessage, times(1)).setRecipient(eq(Message.RecipientType.TO), addressCaptor.capture());
            assertEquals(RAW_USER_EMAIL, addressCaptor.getValue().toString());
        }

        @Test
        @DisplayName("Template 엔진을 이용해 본문을 생성해야 한다.")
        void shouldCreatedContextByTemplateEngine() throws Exception {
            MimeMessage mimeMessage = mock(MimeMessage.class);
            ArgumentCaptor<Context> contextCaptor = ArgumentCaptor.forClass(Context.class);

            MimeMessagePreparator preparator = listener.createMessage(EVENT);
            preparator.prepare(mimeMessage);

            verify(engine, times(1)).process(eq(UserGeneratedCredentialsKeyEventListener.TEMPLATE_LOCATION), contextCaptor.capture());
            verify(mimeMessage, times(1)).setContent(EMAIL_TEMPLATE, "text/html");
            assertEquals(RAW_USERNAME, contextCaptor.getValue().getVariable(UserGeneratedCredentialsKeyEventListener.USERNAME_VARIABLE));
            assertEquals(RAW_USER_EMAIL, contextCaptor.getValue().getVariable(UserGeneratedCredentialsKeyEventListener.USER_EMAIL_VARIABLE));
            assertEquals(RAW_KEY, contextCaptor.getValue().getVariable(UserGeneratedCredentialsKeyEventListener.GENERATED_KEY_VARIABLE));
        }
    }
}