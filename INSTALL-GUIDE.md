## 환경
Java 13 (+)  
Gradle 6.0.1 (+)  
Spring Boot 2.2.2  
Spring Security 5.2.1  

## Getting Started
git 을 이용하여 프로젝트를 Pulling 하고 그레들 배치 스크립트를 생성합니다.
```
$ git clone https://github.com/cube8540/oauth-server.git
$ cd oauth-server
$ gradle wrapper --gradle-version=<gradle-version>
```

## application.yml 설정
src/main/resources/application-example.yml의 파일명을 application.yml으로 변경한 후 자신의 데이터베이스 경로 및 환경을 설정 합니다.
아래는 h2 데이터베이스를 사용하는 것을 가정한 application.yml 작성 예시 입니다.
```
src/main/resources/application.yml

spring:
  mail:
    default-encoding: UTF-8
    host: smtp.server.com
    username: username
    password: password
    port: 1111
    properties:
      mail:
        smtp:
          auth: true
          connectiontimeout: 5000
          timeout: 5000
          writetimeout: 5000
          starttls:
            enable: true
    protocol: smtp
    test-connection: true
  datasource:
    hikari:
      username: testdb
      password: testdb
      auto-commit: off
      connection-test-query: select 1
      validation-timeout: 7200000
      minimum-idle: 1
      maximum-pool-size: 10
      connection-timeout: 5000
    driver-class-name: org.h2.Driver
    url: jdbc:h2:mem:oauth_authorization_server
    sql-script-encoding: UTF-8
    platform: h2
    initialization-mode: always
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: true
front:
  endpoint:
    register-page: http://localhost:8080/front/register
    forgot-password-page: http://localhost:8080/front/forgot-password
```
- spring.datasource

spring.datasource는 데이터베이스의 연결 정보가 설정되며 spring.datasource.platform은 서버 시작시 실행할 테이블 생성 스크립트와
기본 설정 데이터 삽입 스크립트를 결정합니다. 현재 [mariadb](./src/main/resources/schema-mariadb.sql),
[mysql](./src/main/resources/schema-mysql.sql), [h2](./src/main/resources/schema-h2.sql)를 지원 하고 있습니다.

- spring.mail

spring.mail 은 새 계정을 등록했을시 해당 계정에 인증키가 포함된 이메일을 발송하게 됩니다. 만약 이메일을 발송하고 싶지 않을시
spring.mail 옵션은 지워주시면 됩니다. 이메일의 템플릿은 아래 HTML 파일을 수정하여 변경 하실 수 있습니다.


[계정 인증키 발송 이메일 템플릿](src/main/resources/templates/email/user-generated-key-mail-template.html)

- front.endpoint

front.endpoint는 새 계정 생성과 패스워드 분실에 대한 페이지의 엔드 포인트를 설정합니다. 현재 개발된 프론트 페이지는 로그인 화면과
OAuth2 인증 코드 방식의 인가 페이지 두 화면을 뿐임으로 새 계정 생성과 패스워드 분실에 대한 페이지는 따로 개발해야 합니다.

## Build and start
아래의 명령어로 서버를 시작할 수 있습니다.
```
$ gradlew bootRun --args='--spring.profiles.active=local'
```
혹은 그레들의 bootJar 테스킹을 이용하여 빌드하고 서버를 시작합니다.
```
$ gradle bootJar
$ java -jar -Dspring.profiles.active=local build/libs/authentication-<version>.jar
```

## Default Username/Password
```
Username: admin
Password: admin
```