# JWT Token Testing with REST Assured

This project demonstrates a comprehensive approach to testing JWT token validation and verification in Java applications using REST Assured and JUnit 5.

## Overview

JSON Web Tokens (JWT) are a standard for securely transmitting information between parties as a JSON object. This project provides:

1. A flexible JWT token generator supporting multiple algorithms (RS256, RS512, HS256, ES256)
2. Verification utilities to validate token integrity and claims
3. Comprehensive test cases for various JWT security scenarios
4. Integration with REST Assured for API testing

## Features

- **Multiple Algorithm Support**: Test tokens signed with RSA, HMAC, and Elliptic Curve algorithms
- **Security Testing**: Validation for token tampering, expiration, and signature verification
- **Custom Claims**: Support for various data types and nested structures in token payloads
- **Role-Based Access Testing**: Framework for testing different access levels with JWT tokens

## Getting Started

### Prerequisites

- Java 11 or higher
- Maven

### Installation

Clone the repository and build with Maven:

```bash
git clone https://github.com/naveenanimation20/jwt-token-testing.git
cd jwt-testing
mvn clean install
```

## Project Structure

```
.
├── pom.xml
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── nal/
│   │               └── jwt/
│   │                   └── MockJwtGenerator.java
│   └── test/
│       └── java/
│           └── com/
│               └── nal/
│                   └── jwt/
│                       └── test/
│                           └── JwtTokenVerificationTest.java
```

## Usage

### Generating JWT Tokens

```java
// Create token payload
Map<String, Object> payload = new HashMap<>();
payload.put("role", "admin");
payload.put("permissions", Arrays.asList("read", "write", "delete"));

// Generate token with RS256 algorithm, 10 minute expiration
String token = MockJwtGenerator.generateMockJWT("RS256", payload, 600, "user123");
```

### Verifying Tokens

```java
// Verify and decode token
Map<String, Object> claims = MockJwtGenerator.verifyMockJWT(token, "RS256");

// Access claims
String subject = (String) claims.get("sub");
String role = (String) claims.get("role");
```

### API Testing with REST Assured

```java
// Test API access with token
given()
    .header("Authorization", "Bearer " + token)
.when()
    .get("/api/protected-resource")
.then()
    .statusCode(200)
    .body("access", equalTo("granted"));
```

## Test Cases

The project includes the following test scenarios:

- Basic token validation with different algorithms (RS256, RS512, HS256, ES256)
- Expired token detection
- Token tampering detection
- Custom claims validation
- Role-based access control testing

## Security Considerations

- Uses proper key lengths for each algorithm (2048-bit RSA, 256-bit secrets for HMAC)
- Validates token integrity against tampering
- Tests proper expiration time handling
- Verifies that signature validation works correctly

## Dependencies

- [REST Assured](https://rest-assured.io/) - For API testing
- [JJWT](https://github.com/jwtk/jjwt) - For JWT token creation and validation
- [JUnit 5](https://junit.org/junit5/) - For testing framework

## Key Implementation Notes

1. The `MockJwtGenerator` class handles token generation and verification for all supported algorithms
2. Test classes verify both the positive cases (valid tokens) and negative cases (tampered tokens, expired tokens)
3. Various token payloads demonstrate how to handle different claim types and structures

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Naveen AutomationLabs

## License

This project is licensed under the MIT License
