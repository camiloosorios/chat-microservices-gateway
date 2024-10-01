package com.bosorio.app.gateway_microservice.filter;

import com.bosorio.app.gateway_microservice.service.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.ArrayList;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (bearerToken != null) {
            String token = bearerToken.substring(7);
            if (jwtService.validateToken(token)) {
                return Mono.fromCallable(() -> {
                            String userId = jwtService.getClaims(token).getSubject();
                            Authentication authentication =
                                    new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            return authentication;
                        })
                        .subscribeOn(Schedulers.boundedElastic())
                        .flatMap(authentication -> chain.filter(exchange)
                                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication)));
            }
        }
            return chain.filter(exchange);
    }
}