package com.nal.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;

/**
 * 
 * @author naveenautomationlabs
 *
 */
public class MockJwtGenerator {

    // RSA key pair for RS256 and RS512 algorithms
    private static final KeyPair rsaKeyPair;
    
    // EC key pair for ES256 algorithm
    private static final KeyPair ecKeyPair;
    
    // Secret key for HS256 algorithm - must be at least 256 bits (32 bytes) for HS256
    private static final SecretKey hsSecret = Keys.hmacShaKeyFor(
            "supersecretkeythatisatleast32byteslong1234567890abcdefghijklmnopqrstuvwxyz".getBytes());
    
    static {
        try {
            // Generate RSA key pair (2048-bit)
            KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            rsaGenerator.initialize(2048);
            rsaKeyPair = rsaGenerator.generateKeyPair();
            
            // Generate EC key pair (prime256v1 curve)
            KeyPairGenerator ecGenerator = KeyPairGenerator.getInstance("EC");
            ecGenerator.initialize(new ECGenParameterSpec("secp256r1")); // prime256v1 equivalent
            ecKeyPair = ecGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to initialize key pairs", e);
        }
    }
    
    /**
     * Generates a mock JWT token with the specified algorithm, payload, expiration time, and subject
     * 
     * @param algorithm The signing algorithm to use
     * @param payload Additional claims to include in the token
     * @param expiresInSeconds Token expiration time in seconds
     * @param sub The subject claim value
     * @return A signed JWT token
     */
    public static String generateMockJWT(String algorithm, Map<String, Object> payload, 
                                        long expiresInSeconds, String sub) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiresInSeconds * 1000);
        
        switch (algorithm) {
            case "RS256":
                return Jwts.builder()
                        .setClaims(payload)
                        .setSubject(sub)
                        .setIssuedAt(now)
                        .setExpiration(expiryDate)
                        .signWith((RSAPrivateKey) rsaKeyPair.getPrivate(), SignatureAlgorithm.RS256)
                        .compact();
            case "RS512":
                return Jwts.builder()
                        .setClaims(payload)
                        .setSubject(sub)
                        .setIssuedAt(now)
                        .setExpiration(expiryDate)
                        .signWith((RSAPrivateKey) rsaKeyPair.getPrivate(), SignatureAlgorithm.RS512)
                        .compact();
            case "HS256":
                return Jwts.builder()
                        .setClaims(payload)
                        .setSubject(sub)
                        .setIssuedAt(now)
                        .setExpiration(expiryDate)
                        .signWith(hsSecret, SignatureAlgorithm.HS256)
                        .compact();
            case "ES256":
                return Jwts.builder()
                        .setClaims(payload)
                        .setSubject(sub)
                        .setIssuedAt(now)
                        .setExpiration(expiryDate)
                        .signWith((ECPrivateKey) ecKeyPair.getPrivate(), SignatureAlgorithm.ES256)
                        .compact();
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }
    
    /**
     * Verifies and decodes a JWT token with the specified algorithm
     * 
     * @param token The JWT token to verify
     * @param algorithm The algorithm used to sign the token
     * @return The decoded token claims
     */
    public static Map<String, Object> verifyMockJWT(String token, String algorithm) {
        try {
            switch (algorithm) {
                case "RS256":
                case "RS512":
                    return Jwts.parserBuilder()
                            .setSigningKey((RSAPublicKey) rsaKeyPair.getPublic())
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
                case "HS256":
                    return Jwts.parserBuilder()
                            .setSigningKey(hsSecret)
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
                case "ES256":
                    return Jwts.parserBuilder()
                            .setSigningKey((ECPublicKey) ecKeyPair.getPublic())
                            .build()
                            .parseClaimsJws(token)
                            .getBody();
                default:
                    throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
        } catch (Exception e) {
            throw new RuntimeException("Token verification failed: " + e.getMessage(), e);
        }
    }
    
    // Getters for public keys (useful for external verification)
    public static RSAPublicKey getRsaPublicKey() {
        return (RSAPublicKey) rsaKeyPair.getPublic();
    }
    
    public static ECPublicKey getEcPublicKey() {
        return (ECPublicKey) ecKeyPair.getPublic();
    }
}