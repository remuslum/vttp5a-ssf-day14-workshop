FROM openjdk:23-jdk

ARG APP_DIR=/app

WORKDIR ${APP_DIR}

COPY .mvn .mvn
COPY src src
COPY pom.xml .
COPY mvnw . 
COPY mvnw.cmd .

RUN ./mvnw clean package -Dmaven.tests.skip=true

ENV PORT=3000
ENV INSTANCE_NAME="Remus-dov-bear"
ENV INSTANCE_HASH="abc123"

EXPOSE ${PORT}

ENTRYPOINT java -jar target/dovbear-0.0.1-SNAPSHOT.jar --name=${INSTANCE_NAME} --hash=${INSTANCE_HASH}
