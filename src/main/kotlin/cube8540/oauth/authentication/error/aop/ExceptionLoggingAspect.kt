package cube8540.oauth.authentication.error.aop

import cube8540.oauth.authentication.error.ServiceException
import cube8540.oauth.authentication.error.ServiceInvalidException
import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class ExceptionLoggingAspect {

    private val logger: Logger = LoggerFactory.getLogger(this::class.java)

    @Around(value = "@annotation(org.springframework.web.bind.annotation.ExceptionHandler)")
    fun loggingException(joinPoint: ProceedingJoinPoint): Any {
        printStackTrace(joinPoint.args)
        return joinPoint.proceed()
    }

    private fun printStackTrace(args: Array<Any>) {
        for (arg in args) {
            when (arg) {
                is ServiceException -> {
                    logger.info("Throws service exception {} {}", arg.code, arg.message)
                }
                is ServiceInvalidException -> {
                    logger.info("Throws service exception {}", arg.errors)
                }
                is Exception -> {
                    logger.error("Throws error", arg)
                }
            }
        }
    }
}