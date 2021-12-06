package ru.on8off.security.jwt;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.util.MultiValueMap;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerTest {
    String host = "http://localhost:";
    @LocalServerPort
    int port;
    @Autowired
    TestRestTemplate testRestTemplate;

    @Test
    void testLogin() {
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.put("username", List.of("admin1"));
        headers.put("password", List.of("admin123"));
        var response = testRestTemplate.exchange(host + port + "/auth/login", HttpMethod.POST, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        System.out.println(response.getBody());

        headers = new HttpHeaders();
        headers.put("username", List.of("admin"));
        headers.put("password", List.of("admin1234"));
        response = testRestTemplate.exchange(host + port + "/auth/login", HttpMethod.POST, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        System.out.println(response.getBody());


        headers.put("username", List.of("admin"));
        headers.put("password", List.of("admin123"));
        response = testRestTemplate.exchange(host + port + "/auth/login", HttpMethod.POST, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());
    }
}