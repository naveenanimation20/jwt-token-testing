package com.nal.jwt.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import com.nal.jwt.MockJwtGenerator;

/**
 * 
 * @author naveenautomationlabs
 *
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class JwtTokenVerificationTest {

    @BeforeAll
    public void setup() {
        // Setup if needed - for a real API test, you would specify the baseURI here
        // RestAssured.baseURI = "https://your-api-endpoint.com";
    }

    @Test
    public void validateJwtTokenWithRS512() {
        // Generate a random subject (similar to faker in the JavaScript example)
        String customSub = generateRandomNumericString(10);
        
        // Create payload with admin role and feature access
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "admin");
        mockPayload.put("featureAccess", Arrays.asList("reports", "dashboard"));
        
        // Generate token
        String token = MockJwtGenerator.generateMockJWT("RS512", mockPayload, 600, customSub);
        
        // Verify token
        Map<String, Object> decodedToken = MockJwtGenerator.verifyMockJWT(token, "RS512");
        
        // Assert token properties
        assertNotNull(decodedToken);
        assertEquals(customSub, decodedToken.get("sub"));
        assertEquals("admin", decodedToken.get("role"));
        assertTrue(decodedToken.get("featureAccess") instanceof List);
        
        @SuppressWarnings("unchecked")
        List<String> featureAccess = (List<String>) decodedToken.get("featureAccess");
        assertTrue(featureAccess.contains("reports"));
        assertTrue(featureAccess.contains("dashboard"));
        
        // For a real API test, you would make an actual request with the token:
        /*
        given()
            .header("Authorization", "Bearer " + token)
        .when()
            .get("/secure-endpoint")
        .then()
            .statusCode(200)
            .body("isAuthenticated", equalTo(true))
            .body("role", equalTo("admin"));
        */
    }
    
    @Test
    public void validateJwtTokenWithRS256() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "editor");
        mockPayload.put("featureAccess", Arrays.asList("edit", "publish"));
        
        String token = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 600, customSub);
        
        Map<String, Object> decodedToken = MockJwtGenerator.verifyMockJWT(token, "RS256");
        
        assertNotNull(decodedToken);
        assertEquals(customSub, decodedToken.get("sub"));
        assertEquals("editor", decodedToken.get("role"));
        assertTrue(decodedToken.get("featureAccess") instanceof List);
        
        @SuppressWarnings("unchecked")
        List<String> featureAccess = (List<String>) decodedToken.get("featureAccess");
        assertTrue(featureAccess.contains("edit"));
        assertTrue(featureAccess.contains("publish"));
    }
    
    @Test
    public void validateJwtTokenWithHS256() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "user");
        mockPayload.put("permissions", Arrays.asList("read"));
        
        String token = MockJwtGenerator.generateMockJWT("HS256", mockPayload, 600, customSub);
        
        Map<String, Object> decodedToken = MockJwtGenerator.verifyMockJWT(token, "HS256");
        
        assertNotNull(decodedToken);
        assertEquals(customSub, decodedToken.get("sub"));
        assertEquals("user", decodedToken.get("role"));
        assertTrue(decodedToken.get("permissions") instanceof List);
        
        @SuppressWarnings("unchecked")
        List<String> permissions = (List<String>) decodedToken.get("permissions");
        assertTrue(permissions.contains("read"));
    }
    
    @Test
    public void validateJwtTokenWithES256() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "superadmin");
        mockPayload.put("featureAccess", Arrays.asList("all"));
        
        String token = MockJwtGenerator.generateMockJWT("ES256", mockPayload, 600, customSub);
        
        Map<String, Object> decodedToken = MockJwtGenerator.verifyMockJWT(token, "ES256");
        
        assertNotNull(decodedToken);
        assertEquals(customSub, decodedToken.get("sub"));
        assertEquals("superadmin", decodedToken.get("role"));
        assertTrue(decodedToken.get("featureAccess") instanceof List);
        
        @SuppressWarnings("unchecked")
        List<String> featureAccess = (List<String>) decodedToken.get("featureAccess");
        assertTrue(featureAccess.contains("all"));
    }
    
    @Test
    public void validateExpiredToken() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "user");
        
        // Generate token that expires immediately (0 seconds)
        String token = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 0, customSub);
        
        // Wait a moment to ensure token expiration
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Verify the token should fail with an exception
        Exception exception = assertThrows(
            RuntimeException.class,
            () -> MockJwtGenerator.verifyMockJWT(token, "RS256")
        );
        
        assertTrue(exception.getMessage().contains("expired"));
    }
    
    @Test
    public void validateTokenWithInvalidSignature() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "user");
        
        // Generate token with RS256
        String token = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 600, customSub);
        
        // Try to verify with wrong algorithm
        Exception exception = assertThrows(
            RuntimeException.class,
            () -> MockJwtGenerator.verifyMockJWT(token, "HS256")
        );
        
        assertTrue(exception.getMessage().contains("Token verification failed"));
    }
    
    // Helper method to generate random numeric string (similar to faker.string.numeric)
    private String generateRandomNumericString(int length) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(random.nextInt(10));
        }
        return sb.toString();
    }
    
    @Test
    public void validateTamperedToken() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "user");
        mockPayload.put("permissions", Arrays.asList("read"));
        
        String token = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 600, customSub);
        
        // Tamper with the token by changing a character in the payload section
        String[] tokenParts = token.split("\\.");
        if (tokenParts.length == 3) {
            // Modify a character in the payload section (middle part)
            char[] payloadChars = tokenParts[1].toCharArray();
            if (payloadChars.length > 5) {
                payloadChars[5] = payloadChars[5] == 'A' ? 'B' : 'A'; // Modify a character
                tokenParts[1] = new String(payloadChars);
            }
            
            // Reassemble the token (this will have an invalid signature)
            String tamperedToken = tokenParts[0] + "." + tokenParts[1] + "." + tokenParts[2];
            
            // Verification should fail
            Exception exception = assertThrows(
                RuntimeException.class,
                () -> MockJwtGenerator.verifyMockJWT(tamperedToken, "RS256")
            );
            
            assertTrue(exception.getMessage().contains("Token verification failed"));
        }
    }
    
    @Test
    public void validateDifferentExpirationTimes() {
        String customSub = generateRandomNumericString(10);
        Map<String, Object> mockPayload = new HashMap<>();
        mockPayload.put("role", "user");
        
        // Test very short expiration time (1 second)
        String shortLivedToken = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 1, customSub);
        
        // Verify token works immediately
        Map<String, Object> decodedShortLivedToken = MockJwtGenerator.verifyMockJWT(shortLivedToken, "RS256");
        assertNotNull(decodedShortLivedToken);
        assertEquals(customSub, decodedShortLivedToken.get("sub"));
        
        // Wait for expiration
        try {
            Thread.sleep(1100); // Wait just over 1 second
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Token should be expired now
        Exception exception = assertThrows(
            RuntimeException.class,
            () -> MockJwtGenerator.verifyMockJWT(shortLivedToken, "RS256")
        );
        
        assertTrue(exception.getMessage().contains("expired"));
        
        // Test long expiration time (1 hour)
        String longLivedToken = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 3600, customSub);
        Map<String, Object> decodedLongLivedToken = MockJwtGenerator.verifyMockJWT(longLivedToken, "RS256");
        assertNotNull(decodedLongLivedToken);
        
        // The expiration time should be approximately 1 hour in the future
        long expirationTime = ((Number) decodedLongLivedToken.get("exp")).longValue();
        long currentTime = System.currentTimeMillis() / 1000;
        
        // Should expire in roughly 3600 seconds (allow small margin for test execution time)
        assertTrue(expirationTime > currentTime + 3590);
        assertTrue(expirationTime < currentTime + 3610);
    }
    
    @Test
    public void validateCustomClaims() {
        String customSub = generateRandomNumericString(10);
        
        Map<String, Object> mockPayload = new HashMap<>();
        // Add various custom claims of different types
        mockPayload.put("userId", 12345);
        mockPayload.put("email", "test@example.com");
        mockPayload.put("isActive", true);
        mockPayload.put("lastLogin", "2023-04-13T10:30:00Z");
        mockPayload.put("preferences", new HashMap<String, Object>() {{
            put("theme", "dark");
            put("notifications", true);
            put("language", "en-US");
        }});
        
        String token = MockJwtGenerator.generateMockJWT("RS256", mockPayload, 600, customSub);
        
        Map<String, Object> decodedToken = MockJwtGenerator.verifyMockJWT(token, "RS256");
        
        // Verify all custom claims exist and have correct values
        assertEquals(12345, ((Number) decodedToken.get("userId")).intValue());
        assertEquals("test@example.com", decodedToken.get("email"));
        assertEquals(true, decodedToken.get("isActive"));
        assertEquals("2023-04-13T10:30:00Z", decodedToken.get("lastLogin"));
        
        @SuppressWarnings("unchecked")
        Map<String, Object> preferences = (Map<String, Object>) decodedToken.get("preferences");
        assertNotNull(preferences);
        assertEquals("dark", preferences.get("theme"));
        assertEquals(true, preferences.get("notifications"));
        assertEquals("en-US", preferences.get("language"));
    }
    
    @Test
    public void testRoleBasedAccessWithRestAssured() {
        // This is a simulated test that shows how to use the tokens with REST Assured
        // In a real scenario, you would have an actual API to test against
        
        // Create tokens for different roles
        String adminSub = generateRandomNumericString(10);
        Map<String, Object> adminPayload = new HashMap<>();
        adminPayload.put("role", "admin");
        adminPayload.put("permissions", Arrays.asList("read", "write", "delete"));
        String adminToken = MockJwtGenerator.generateMockJWT("RS256", adminPayload, 600, adminSub);
        
        String userSub = generateRandomNumericString(10);
        Map<String, Object> userPayload = new HashMap<>();
        userPayload.put("role", "user");
        userPayload.put("permissions", Arrays.asList("read"));
        String userToken = MockJwtGenerator.generateMockJWT("RS256", userPayload, 600, userSub);
        
        // MOCK: Define what the response would be for each token
        // In a real test, these would be actual API calls
        
        /* 
        // Admin token should have access to admin endpoint
        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .get("/api/admin/resources")
        .then()
            .statusCode(200)
            .body("success", equalTo(true))
            .body("message", equalTo("Admin access granted"));
            
        // User token should NOT have access to admin endpoint
        given()
            .header("Authorization", "Bearer " + userToken)
        .when()
            .get("/api/admin/resources")
        .then()
            .statusCode(403)
            .body("success", equalTo(false))
            .body("message", equalTo("Insufficient permissions"));
            
        // Both tokens should have access to user endpoint
        given()
            .header("Authorization", "Bearer " + adminToken)
        .when()
            .get("/api/user/profile")
        .then()
            .statusCode(200)
            .body("success", equalTo(true));
            
        given()
            .header("Authorization", "Bearer " + userToken)
        .when()
            .get("/api/user/profile")
        .then()
            .statusCode(200)
            .body("success", equalTo(true));
        */
        
        // For now, just verify token claims to demonstrate different role tokens
        Map<String, Object> decodedAdminToken = MockJwtGenerator.verifyMockJWT(adminToken, "RS256");
        Map<String, Object> decodedUserToken = MockJwtGenerator.verifyMockJWT(userToken, "RS256");
        
        assertEquals("admin", decodedAdminToken.get("role"));
        assertEquals("user", decodedUserToken.get("role"));
        
        @SuppressWarnings("unchecked")
        List<String> adminPermissions = (List<String>) decodedAdminToken.get("permissions");
        @SuppressWarnings("unchecked")
        List<String> userPermissions = (List<String>) decodedUserToken.get("permissions");
        
        assertTrue(adminPermissions.contains("delete"));
        assertFalse(userPermissions.contains("delete"));
    }
}