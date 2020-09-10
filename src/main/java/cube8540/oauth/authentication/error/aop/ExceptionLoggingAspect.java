package cube8540.oauth.authentication.error.aop;

import cube8540.oauth.authentication.error.ServiceException;
import cube8540.oauth.authentication.error.ServiceInvalidException;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Slf4j
@Aspect
@Component
public class ExceptionLoggingAspect {

    @Around(value = "@annotation(org.springframework.web.bind.annotation.ExceptionHandler)")
    public Object loggingException(ProceedingJoinPoint joinPoint) throws Throwable {
        printStackTrace(joinPoint.getArgs());
        return joinPoint.proceed();
    }

    private void printStackTrace(Object[] args) {
        for (Object arg : args) {
            if (arg instanceof ServiceException) {
                log.info("Throws service exception {} {}", ((ServiceException) arg).getCode(),
                        ((ServiceException) arg).getMessage());
            } else if (arg instanceof ServiceInvalidException) {
                log.info("Throws service invalid exception {}", ((ServiceInvalidException) arg).getErrors());
            } else if (arg instanceof Exception) {
                log.error("throws error ", (Exception) arg);
            }
        }
    }
}
