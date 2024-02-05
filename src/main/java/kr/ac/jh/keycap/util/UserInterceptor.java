package kr.ac.jh.keycap.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.model.UserVo;

public class UserInterceptor extends HandlerInterceptorAdapter {

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		HttpSession session = request.getSession();
		
		UserVo user = (UserVo) session.getAttribute("user");
		AdminVo admin = (AdminVo) session.getAttribute("admin");
		
		if(user != null) {
			return true;
		}
		
		else if(admin != null) {
			return true;
					
		} else {
			response.sendRedirect("/login");
		}
		
		return false;
		
	}

}
