package com.kucw.security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class MySecurityConfig {

    @Bean
    public InMemoryUserDetailsManager userDetailsManager() {
        UserDetails userTest1 = User
                .withUsername("test1")
                .password("{noop}111")
                .roles("ADMIN", "USER")
                .build();

        UserDetails userTest2 = User
                .withUsername("test2")
                .password("{noop}222")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userTest1, userTest2);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf -> csrf.disable())
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults())

                .authorizeHttpRequests(request -> request
                        .anyRequest().authenticated()
                )
                .cors(cors ->cors.configurationSource(createCorsConfig()))

                .build();
    }
    private CorsConfigurationSource createCorsConfig(){
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("*")); //後端允許的請求來源有哪些 例如:"http://example.com"
        config.setAllowedHeaders(List.of("*")); //後端允許的請求request header 有哪些
        config.setAllowedMethods(List.of("*")); //後端允許的請求http method 有哪些 例如: GET POST
        //config.setAllowCredentials(true); //後端是否允許前端帶上Cookies
        config.setMaxAge(3600L); //表示瀏覽器一開始會先傳送的prelight請求 結果可以背瀏覽器cache的秒數

        UrlBasedCorsConfigurationSource source =new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",config);

        return source;
    }
    //瀏覽器會先發出prelight請球 詢問後段允許哪些 origin，後段在response header中告知允許的 origin ，
    // 瀏覽器根據後端返回的值檢查html頁面發出的請求，來是否符合後端的要求
}
