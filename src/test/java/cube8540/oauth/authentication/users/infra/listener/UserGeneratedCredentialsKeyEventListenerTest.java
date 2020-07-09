package cube8540.oauth.authentication.users.infra.listener;

import cube8540.oauth.authentication.users.domain.UserCredentialsKey;
import cube8540.oauth.authentication.users.domain.UserEmail;
import cube8540.oauth.authentication.users.domain.UserGeneratedCredentialsKeyEvent;
import cube8540.oauth.authentication.users.domain.Username;
import org.junit.jupiter.api.DisplayName;
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

    private static final String EMAIL_SUBJECT = "SUBJECT";

    private static final UserGeneratedCredentialsKeyEvent EVENT = new UserGeneratedCredentialsKeyEvent(USERNAME, EMAIL, KEY);

    @Test
    @DisplayName("JavaMailSender 인터페이스가 null 일시 이메일 발송")
    void sendEmailJavaMailSenderIsNull() {
        UserGeneratedCredentialsKeyEventListener listener = new UserGeneratedCredentialsKeyEventListener();

        assertDoesNotThrow(() -> listener.sendCredentialsKeyEmail(EVENT));
    }

    @Test
    @DisplayName("이메일 발송")
    void sendEmail() {
        JavaMailSender sender = mock(JavaMailSender.class);
        UserGeneratedCredentialsKeyEventListener listener = new UserGeneratedCredentialsKeyEventListener(sender, mock(ITemplateEngine.class));

        listener.sendCredentialsKeyEmail(EVENT);
        verify(sender, times(1)).send(any(MimeMessagePreparator.class));
    }

    @Test
    @DisplayName("이메일 제목 설정")
    void setEmailSubject() throws Exception {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        JavaMailSender sender = mock(JavaMailSender.class);
        ITemplateEngine engine = mock(ITemplateEngine.class);
        UserGeneratedCredentialsKeyEventListener listener = new UserGeneratedCredentialsKeyEventListener(sender, engine);

        listener.setSubject(EMAIL_SUBJECT);
        when(engine.process(anyString(), any())).thenReturn(EMAIL_TEMPLATE);

        MimeMessagePreparator preparator = listener.createMessage(EVENT);
        preparator.prepare(mimeMessage);
        verify(mimeMessage, times(1)).setSubject(EMAIL_SUBJECT);
    }

    @Test
    @DisplayName("이메일 수신자 설정")
    void setEmailReceiver() throws Exception {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        JavaMailSender sender = mock(JavaMailSender.class);
        ITemplateEngine engine = mock(ITemplateEngine.class);
        UserGeneratedCredentialsKeyEventListener listener = new UserGeneratedCredentialsKeyEventListener(sender, engine);
        ArgumentCaptor<Address> addressCaptor = ArgumentCaptor.forClass(Address.class);

        when(engine.process(anyString(), any())).thenReturn(EMAIL_TEMPLATE);

        MimeMessagePreparator preparator = listener.createMessage(EVENT);
        preparator.prepare(mimeMessage);
        verify(mimeMessage, times(1)).setRecipient(eq(Message.RecipientType.TO), addressCaptor.capture());
        assertEquals(RAW_USER_EMAIL, addressCaptor.getValue().toString());
    }

    @Test
    @DisplayName("이메일 본문 생성")
    void setEmailContext() throws Exception {
        MimeMessage mimeMessage = mock(MimeMessage.class);
        JavaMailSender sender = mock(JavaMailSender.class);
        ITemplateEngine engine = mock(ITemplateEngine.class);
        UserGeneratedCredentialsKeyEventListener listener = new UserGeneratedCredentialsKeyEventListener(sender, engine);
        ArgumentCaptor<Context> contextCaptor = ArgumentCaptor.forClass(Context.class);

        when(engine.process(anyString(), any())).thenReturn(EMAIL_TEMPLATE);

        MimeMessagePreparator preparator = listener.createMessage(EVENT);
        preparator.prepare(mimeMessage);
        verify(engine, times(1)).process(eq(UserGeneratedCredentialsKeyEventListener.TEMPLATE_LOCATION), contextCaptor.capture());
        verify(mimeMessage, times(1)).setContent(EMAIL_TEMPLATE, "text/html");
        assertEquals(RAW_USERNAME, contextCaptor.getValue().getVariable(UserGeneratedCredentialsKeyEventListener.USERNAME_VARIABLE));
        assertEquals(RAW_USER_EMAIL, contextCaptor.getValue().getVariable(UserGeneratedCredentialsKeyEventListener.USER_EMAIL_VARIABLE));
        assertEquals(RAW_KEY, contextCaptor.getValue().getVariable(UserGeneratedCredentialsKeyEventListener.GENERATED_KEY_VARIABLE));
    }
}