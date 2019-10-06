package com.cute.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author baobao
 */
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);
        //定制请求的授权规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3")
                //.anyRequest().authenticated()
                .and()//开启自动配置的登录功能,效果,如果没有登录,没有权限就会来到登录页面
                .formLogin()//1. /login来到登录页面 2. 重定向到/login?error表示登录失败 3. 更多详细规定 4.默认post形式的/login代表处理登录
                .usernameParameter("user")
                .passwordParameter("pwd")
                .loginPage("/userlogin").loginProcessingUrl("/userlogin")
                //自定义登录界面
                .and()//开启自动配置注销
                .logout().logoutSuccessUrl("/")//注销成功来到首页 1.访问 /logout 表示用户注销 ,清空session 2. 注销成功会返回/login?logout页面
                .and()//开启记住我功能
                .rememberMe().rememberMeParameter("remember");
        //登录成功后,将cookie发给浏览器保存,以后登录带上这个cookie,点击注销,会清楚cookie
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication()
                .withUser("zhangsan").password(encoder.encode("123456")).roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password(encoder.encode("123456")).roles("VIP2","VIP3")
                .and()
                .withUser("wangwu").password(encoder.encode("123456")).roles("VIP1","VIP3");
    }
    /**
     * 这是另一种解决方法
     *  @Bean
     *     @Override
     *     public UserDetailsService userDetailsService() {
     *         UserDetails user =
     *              User.withDefaultPasswordEncoder()
     *                 .username("user")
     *                 .password("password")
     *                 .roles("USER")
     *                 .build();
     *
     *         return new InMemoryUserDetailsManager(user);
     *     }
     */
}
