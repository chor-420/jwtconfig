package com.fresco.ecommerce.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.fresco.ecommerce.models.User;
import com.fresco.ecommerce.service.UserAuthService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtil {
	@Autowired
	UserAuthService userDetails;

	public User getUser(final String token) {
		String username = extractUsername(token);
		return userDetails.loadUserByUsername(username);
	}

	public String generateToken(String username) {
 		Map<String, Object> claims = new HashMap<>(); 
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2))
				.signWith(SignatureAlgorithm.HS256, "secret").compact();
		 
	}

	public boolean validateToken(final String token,UserDetails user) {
  		return  user.getUsername().equals(extractUsername(token)) && extractExpiration(token).after(new Date());
	}

	public Claims extractClaims(String token) {
		return Jwts.parser().setSigningKey("secret").parseClaimsJws(token).getBody();
	}

	public Date extractExpiration(final String token) {
		return extractClaims(token).getExpiration();
	}
	
	public String extractUsername(final String token) {
		return extractClaims(token).getSubject();
	}
}
