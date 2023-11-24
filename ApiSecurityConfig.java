package com.fresco.ecommerce.config;

import org.springframework.beans.factory.annotation.Autowired;
 import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fresco.ecommerce.service.UserAuthService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	JwtAuthenticationFilter filter;
	@Autowired
	ApiAuthenticationEntryPoint entryPoint;
	@Autowired
	UserAuthService userDetails;

//	@Override
//	public void configure(WebSecurity web) throws Exception {
//
//	}

	@Autowired
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetails).passwordEncoder(getPasswordEndcoder());
 	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests().antMatchers("/api/public/**").permitAll()
				.antMatchers("/api/auth/consumer/**").hasAnyAuthority("CONSUMER")
				.antMatchers("/api/auth/seller/**").hasAnyAuthority("SELLER")
				.anyRequest()
				.authenticated();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		 http.exceptionHandling().authenticationEntryPoint(entryPoint);
		http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
	}

//	@Bean
//	public RegistrationBean jwtAuthFilterRegister(JwtAuthenticationFilter filter) {
//		return null;
//	}

	@Bean
	public PasswordEncoder getPasswordEndcoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}
