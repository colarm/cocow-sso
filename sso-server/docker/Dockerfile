FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /app

COPY pom.xml .
# Pre-download dependencies (cached layer, only invalidated on pom.xml change)
RUN mvn dependency:go-offline -q

COPY src ./src

RUN mvn clean package -DskipTests -q && \
    mv target/*.jar app.jar

FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=builder /app/app.jar .

RUN groupadd -g 1000 sso && \
    useradd -u 1000 -g sso -m -d /app -s /usr/sbin/nologin sso && \
    chown -R sso:sso /app

USER sso

EXPOSE 8080

ENTRYPOINT ["java", "-Djna.tmpdir=/tmp", "-Djava.io.tmpdir=/tmp", "-jar", "app.jar"]
