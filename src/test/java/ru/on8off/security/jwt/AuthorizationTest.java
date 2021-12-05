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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class AuthorizationTest {
    String host = "http://localhost:";
    @LocalServerPort
    int port;
    @Autowired
    TestRestTemplate testRestTemplate;

    @Test
    public void testAdmin(){
        var response = testRestTemplate.getForEntity(host + port + "/getForAdmin", String.class);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.put("username", List.of("admin"));
        headers.put("password", List.of("admin123"));
        response = testRestTemplate.exchange(host + port + "/auth/login", HttpMethod.POST, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());

        var jwt = response.getBody();
        headers = new HttpHeaders();
        headers.put(HttpHeaders.AUTHORIZATION, List.of("Bearer " + jwt));

        response = testRestTemplate.exchange(host + port + "/getForAdmin", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());

        response = testRestTemplate.exchange(host + port + "/getForAdminWithPermissions", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertEquals("ALL DATA", response.getBody());

        response = testRestTemplate.exchange(host + port + "/getForUser", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());

        response = testRestTemplate.exchange(host + port + "/getForUserWithPermissions", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertEquals("ALL DATA", response.getBody());
    }

    @Test
    public void testUser(){
        var response = testRestTemplate.getForEntity(host + port + "/getForUser", String.class);
        Assertions.assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.put("username", List.of("user"));
        headers.put("password", List.of("user123"));
        response = testRestTemplate.exchange(host + port + "/auth/login", HttpMethod.POST, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());

        var jwt = response.getBody();
        headers = new HttpHeaders();
        headers.put(HttpHeaders.AUTHORIZATION, List.of("Bearer " + jwt));

        response = testRestTemplate.exchange(host + port + "/getForUser", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());

        response = testRestTemplate.exchange(host + port + "/getForUserWithPermissions", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertEquals("ALL DATA", response.getBody());

        response = testRestTemplate.exchange(host + port + "/getForAdmin", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        response = testRestTemplate.exchange(host + port + "/getForAdminWithPermissions", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());

        headers = new HttpHeaders();
        headers.put("username", List.of("user2"));
        headers.put("password", List.of("user123"));
        response = testRestTemplate.exchange(host + port + "/auth/login", HttpMethod.POST, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertNotNull(response.getBody());

        jwt = response.getBody();
        headers = new HttpHeaders();
        headers.put(HttpHeaders.AUTHORIZATION, List.of("Bearer " + jwt));
        response = testRestTemplate.exchange(host + port + "/getForUserWithPermissions", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        Assertions.assertEquals(HttpStatus.OK, response.getStatusCode());
        Assertions.assertNull(response.getBody());

    }


}
