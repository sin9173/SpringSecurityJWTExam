package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if(req.getMethod().equals("POST")) {
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth : " + headerAuth);

//            if(headerAuth.equals("cos")) {
//                chain.doFilter(req, res);
//            } else {
//                PrintWriter outPrintWriter = res.getWriter();
//                outPrintWriter.println("인증안됨");
//            }
            chain.doFilter(req, res);
        }
    }
}
