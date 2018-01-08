package com.spring.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static java.util.Collections.emptyList;

public class TokenAuthenticationService {
    static final long EXPIRATIONTIME = 10 * 24 * 60 * 60 * 1000;//864_000_000; // 10 days
    static final String SECRET = "ThisIsASecret"; //Sign tokens with a strong key that is available ONLY to the authentication service
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";

    public static void addAuthentication(HttpServletResponse res, Authentication auth) {
        // TODO encrypt with rsa
        String JWT = Jwts.builder()
                .setSubject(auth.getName())
                .claim("username", auth.getName())
                .claim("roles", auth.getAuthorities())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
                .signWith(SignatureAlgorithm.HS512, SECRET)
                .compact();
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + JWT);
        // exposing the custom header
        res.addHeader("Access-Control-Expose-Headers", "Authorization");
    }

    static Authentication getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if (token != null) {
            // parse the token.
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(SECRET)
                    .parseClaimsJws(token.replace(TOKEN_PREFIX, ""));

            String username = (String) claims.getBody().get("username");

            List<GrantedAuthority> authorities = new ArrayList<>();
            ((Collection<LinkedHashMap<String, String>>) claims.getBody().get("roles"))
                    .forEach(authority -> authorities
                            .add(new SimpleGrantedAuthority(authority.get("authority"))));

            return username != null ?
                    new UsernamePasswordAuthenticationToken(emptyList(), username, authorities) :
                    null;
        }
        return null;
    }
}