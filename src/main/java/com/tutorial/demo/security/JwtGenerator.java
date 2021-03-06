package com.tutorial.demo.security;

import org.springframework.stereotype.Component;

import com.tutorial.demo.model.JwtUser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtGenerator {

	public String generate(JwtUser jwtUser) {

        Claims claims = Jwts.claims()
                .setSubject(jwtUser.getUserName());
        claims.put("userId", String.valueOf(jwtUser.getId()));
        claims.put("role", jwtUser.getRole());
        

        //youtube = it is a secret code, you can use anything else
        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, "youtube")
                .compact();
    }
	
}
