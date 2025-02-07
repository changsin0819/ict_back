FROM eclipse-temurin:17-jdk-alpine
WORKDIR /webserver
COPY ./build/libs/*SNAPSHOT.jar webserver.jar
ENTRYPOINT [ "java","-jar","webserver.jar" ]