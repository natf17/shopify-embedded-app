package com.ppublica.shopify.app;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.DEFINED_PORT)
@ActiveProfiles("test")
public class ApplicationTest {
    // write integration tests run by mvn test that need a server and the entire app running
}
