package org.javaboy.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 对于密码不做加密处理
    /*@Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }*/

    // 加密处理
    // 使用springSecurity的加密方式，尽管明文一样那么加密 后的密文是不一样的
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }



    // 添加设置用户名密码和角色
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //配置用户名密码角色
        auth.inMemoryAuthentication()
                .withUser("javaboy").password("$2a$10$2HZSKk7j3YM6Zcshq7L/GOfUaSZjxv9cVbbhH6/XWYZcynHzEfzX.").roles("admin")
                .and()
                .withUser("江南一点雨").password("$2a$10$GcAmfa6OjnIE9NPjcvZqA.5quk0Gih17nh.0RkUXztnzTZOfvn8n2").roles("user");
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
                // 设置默认的登录页面  '/'一定要加上
                //登录配置
                .loginPage("/login")
                //定义用户名的属性（key）,传递的参数的key为uname
                .usernameParameter("uname")
                //定义密码的属性（key）,传递的参数的key为passwd
                .passwordParameter("passwd")
                // 验证成功
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        // 返回数据类型
                        response.setContentType("application/json;charset=UTF-8");
                        // 获取out
                        PrintWriter out = response.getWriter();

                        //设置值
                        Map<String, Object> map = new HashMap<>();
                        map.put("status",200);
                        map.put("msg",authentication.getPrincipal());

                        //将数据用out流写出
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //验证失败
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        response.setContentType("application/json;charset=UTF-8");
                        PrintWriter out = response.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status",401);
                        if (e instanceof LockedException){
                            map.put("msg","用户被锁定");
                        }else if (e instanceof BadCredentialsException){
                            map.put("msg","用户名密码错误");
                        }else{
                            map.put("msg","登录失败");
                        }

                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                // 与登录相关的接口直接访问
                .permitAll()
                .and()
                // 注销登录
                .logout()
                //注销登录访问url
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.setContentType("application/json;charset=UTF-8");
                        PrintWriter out = response.getWriter();

                        Map<String, Object> map = new HashMap<>();
                        map.put("status",200);
                        map.put("msg","注销成功");

                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                .and()
                // 关闭csrf攻击策略
                .csrf().disable();
    }
}
