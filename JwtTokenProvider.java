package com.retrofilly.retrofilly.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * Author: Edward Tanko <br/>
 * Date: 6/26/19 1:30 AM <br/>
 */

public class JwtTokenProvider {

   // typically from properties file
    private String secretKey = "secret-key";

   // typically from properties file
    private long validityInMilliseconds = 3600000;


    /**
     *  This method create a JWT token with claims.
     *
     * @param userId
     * @param email
     * @param userRole
     * @return
     */
    public String createToken(Long userId, String email, String userRole)  {

        Claims claims = Jwts.claims().setSubject(userId.toString());
        claims.put("id", userId);
        claims.put("email",email);
        claims.put("auth", userRole);
        // feel free to add more claims in the token
        Date now = new Date();
        long expiredMillis = (now.getTime() + validityInMilliseconds);
        Date validity = new Date(expiredMillis);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /**
     * This method verifies if the jwt token is valid or the jwt token has expired
     * otherwise it returns a Map of all the claims for the valid jwt token
     *
     * @param jwtToken
     * @return
     */
    public Map<String, String> validateToken(String jwtToken) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken).getBody();
            String userId = (String) claims.get("id");
            String email = (String) claims.get("email");
            String userRole = (String) claims.get("auth");

            HashMap<String, String> authRetroUser = new HashMap<>();
            authRetroUser.put("userId", userId);
            authRetroUser.put("email", email);
            authRetroUser.put("userRole", userRole);
            return authRetroUser;

        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Expired or invalid JWT jwtToken");
        }
    }


}
