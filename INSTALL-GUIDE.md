## 환경
Java 13 (+)  
Gradle 6.0.1 (+)  
Spring Boot 2.2.2  
Spring Security 5.2.1  

## Getting Started
git 을 이용하여 프로젝트를 Pulling 한다. 그레들 배치 스크립트를 생성한다.
```
$ git clone https://github.com/cube8540/oauth-authentication-server.git
$ cd oauth-authentication-server
$ gradle wrapper --gradle-version=<gradle-version>
```

## application.yml 설정
src/main/resources/application-example.yml의 파일명을 application.yml으로 변경한 후 자신의 데이터베이스 경로 및 환경을 설정 합니다.
아래는 MariaDB를 사용하는 것을 가정한 application.yml 작성 예시 입니다.
```
src/main/resources/application.yml

spring:
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
    driver-class-name: org.mariadb.jdbc.Driver
    url: jdbc:mariadb://localhost:3306/testdb
    sql-script-encoding: UTF-8
  jpa:
    hibernate:
      ddl-auto: create
    show-sql: true
```

## Build and start
그레들의 bootJar 테스킹을 이용하여 빌드하고 서버를 시작합니다.
```
$ gradle bootJar
$ java -jar -Dspring.profiles.active=local build/libs/authentication-1.3.2.jar
``` 