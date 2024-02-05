package kr.ac.jh.keycap.util;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import kr.ac.jh.keycap.model.AdminVo;

public class AdminInterceptor extends HandlerInterceptorAdapter {
	//리팩터링 => 기존의 코드를 불러와서 바꾸는것
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
		HttpSession session = request.getSession();
		
		AdminVo admin = (AdminVo) session.getAttribute("admin");
		
		if(admin == null)
		{
			response.sendRedirect("/loginAdmin");
		}
		else if(admin != null)
		{
			Integer adminState = admin.getAdminState();
			if(adminState != 1)
			{
				response.sendRedirect("/loginAdmin");
			}
			else
			{
				return true;
			}
		}
		
		return false;
	}

}
