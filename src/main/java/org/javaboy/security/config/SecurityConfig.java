package org.javaboy.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 对于密码不做加密处理
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    // 添加设置用户名密码和角色
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //配置用户名密码角色
        auth.inMemoryAuthentication()
                .withUser("javaboy").password("123").roles("admin")
                .and()
                .withUser("江南一点雨").password("456").roles("user");
    }

    // 不同类型的接口使用不同的拦截类型
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                // 访问admin/**路径并且role角色是admin
                .antMatchers("/admin/**").hasRole("admin")
                // 访问user、**路径并且role角色是admin或者user
                .antMatchers("/user/**").hasAnyRole("admin","user")
                // 其他的路径只要登录认证后就可以访问
                .anyRequest().authenticated()
                .and()
                // 表单登录
                .formLogin()
                .loginProcessingUrl("/doLogin")
                // 与登录相关的接口直接访问
                .permitAll()
                .and()
                // 关闭csrf攻击策略
                .csrf().disable();
    }
}
