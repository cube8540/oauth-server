package cube8540.oauth.authentication.users.infra.listener;

import cube8540.oauth.authentication.users.domain.UserGeneratedCredentialsKeyEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;

@Component
public class UserGeneratedCredentialsKeyEventListener {

    protected static final String TEMPLATE_LOCATION = "email/user-generated-key-mail-template";
    protected static final String USERNAME_VARIABLE = "registeredUsername";
    protected static final String USER_EMAIL_VARIABLE = "registeredUserEmail";
    protected static final String GENERATED_KEY_VARIABLE = "generatedKey";

    protected static final String DEFAULT_SUBJECT = "가입 확인 이메일 입니다.";

    private final JavaMailSender mailSender;
    private final ITemplateEngine templateEngine;
    private String subject;

    public UserGeneratedCredentialsKeyEventListener() {
        this(null, null);
    }

    @Autowired(required = false)
    public UserGeneratedCredentialsKeyEventListener(JavaMailSender mailSender, ITemplateEngine engine) {
        this.mailSender = mailSender;
        this.templateEngine = engine;
        this.subject = DEFAULT_SUBJECT;
    }

    @Async("asyncThreadPoolTaskExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMPLETION, classes = UserGeneratedCredentialsKeyEvent.class)
    public void sendCredentialsKeyEmail(UserGeneratedCredentialsKeyEvent event) {
        if (mailSender != null) {
            this.mailSender.send(createMessage(event));
        }
    }

    protected MimeMessagePreparator createMessage(UserGeneratedCredentialsKeyEvent event) {
        return mimeMessage -> {
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage);
            helper.setTo(event.getEmail().getValue());
            helper.setText(templateEngine.process(TEMPLATE_LOCATION, createContext(event)), true);
            helper.setSubject(subject);
        };
    }

    private Context createContext(UserGeneratedCredentialsKeyEvent event) {
        Context context = new Context();

        context.setVariable(USERNAME_VARIABLE, event.getUsername().getValue());
        context.setVariable(USER_EMAIL_VARIABLE, event.getEmail().getValue());
        context.setVariable(GENERATED_KEY_VARIABLE, event.getKey().getKeyValue());

        return context;
    }
}
