FROM eclipse-temurin:25-jdk-alpine AS builder

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN apk add --no-cache maven && \
    mvn clean package -DskipTests && \
    mv target/*.jar app.jar

FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

COPY --from=builder /app/app.jar .

RUN addgroup -g 1000 sso && \
    adduser -D -u 1000 -G sso sso && \
    chown -R sso:sso /app

USER sso

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]
