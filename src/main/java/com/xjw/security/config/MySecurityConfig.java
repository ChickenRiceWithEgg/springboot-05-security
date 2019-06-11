package com.xjw.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @Author: xiejingwei
 * @Date: 2019/6/11 9:36
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    //定义授权规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //默认请求授权规则
        //super.configure(http);

        //定制请求授权规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()   //访问“/”，都可以
                .antMatchers("/level1/**").hasRole("VIP1")   //访问“/level1/”的路径，需要VIP1的角色
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        http.formLogin()
                .usernameParameter("user")
                .passwordParameter("pwd")
                .loginPage("/userlogin"); //当访问没有权限的路径时会自动跳转到"/userlogin"路径下，默认是"/login"（框架自定义进行操作）
        http.logout()
                .logoutSuccessUrl("/");
        http.rememberMe()
                .rememberMeParameter("rememberMe");

        /*
        //开启自动配置的登录功能，效果：如果没有登录，没有权限就会来到登录页面
        http.formLogin()  //默认的登录路径为 /login，
            .usernameParameter("user")   //在自定义的登录页面的表单中，用户和密码的name，需要和这里对应上。
            .passwordParameter("pwd")
            .loginPage("/userlogin");  //自定义的登录路径，编写controller来响应，并返回到自定义的登录页面

        //开启记住我功能
        //登陆成功以后，将cookie发给浏览器保存，以后访问页面带上这个cookie，只要通过检查就可以免登录
        //点击注销之后就会删除这个cookie
        http.rememberMe()   //在默认的登录页面会出现注销的submit
            .rememberMeParameter("rememberMe");  //在自定义的登录页面，会在name="rememberMe"的submit实现注销

        //开启自动配置的注销功能，
        //访问 /logout 实现用户注销，清空session
        http.logout()    //默认的注销请求路径为 /logout 。完成注销之后，默认返回到 /login?logout 页面
            .logoutSuccessUrl("/");   //默认的注销请求路径为 /logout 。完成注销之后，自定义返回到 /  页面
         */

    }

    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //默认认证规则
        //super.configure(auth);

        //定制认证规则
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())   //从这些用户里面来校验用户名和密码，并且根据他们的角色，结合授权规则，来实现他们对不同路径的访问规则
                .withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP2","VIP3")
                .and()
                .withUser("wangwu").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP3");

    }
}
