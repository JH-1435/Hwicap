package kr.ac.jh.keycap.controller;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.UUID;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.service.NaverLoginService;
import kr.ac.jh.keycap.service.UserService;

@Controller
public class NaverController {
	
	@Autowired
	NaverLoginService service;
	
	@Autowired
	UserService userS;
	
	@RequestMapping("/naver/login")
	public String naverLogin(@RequestParam String code, UserVo item, HttpSession session, HttpServletResponse response) {
		
		// 1번 네이버 사용자 코드 확인
		System.out.println("naver_code:" + code);
		
        // 2번 네이버 토큰 확인
		String access_Token = service.getAccessToken(code);
		
		System.out.println("###naver_access_Token#### : " + access_Token);
		
		// 3번  네이버 정보 가져온것 확인 (email을 필수 or 선택하게 하려면 사업자등록 즉 돈을 내야함)
		HashMap<String, Object> userInfo = service.getUserInfo(access_Token);
//		System.out.println("###id#### : " + userInfo.get("id"));
//		System.out.println("###name#### : " + userInfo.get("name"));
//		System.out.println("###mobile#### : " + userInfo.get("mobile"));
//		System.out.println("###email#### : " + userInfo.get("email"));
		
		//4번 네이버 정보 가져온것을 회원가입 or 로그인 처리시키기
		if (userInfo.get("id") != null && userInfo.get("name") != null) {
					
			//네이버 회원 정보를 userVo(user list 확인용)에 넣어줌
			item.setUserId(userInfo.get("id").toString());
			item.setUserName(userInfo.get("name").toString());
			item.setUserAddress(userInfo.get("email").toString());
			item.setUserPw(null);
			item.setUserTel(userInfo.get("mobile").toString());
					
			//네이버 간편로그인 처리
			if(userS.item(item.getUserId()) != null)
			{
				if (userS.oauthLogin(item)) 
				{
					// 토큰 생성(소셜 로그인은 화면이 리다이렉트 되기 때문에 소셜 로그인 화면 리다이렉트 이후 내 url(localhost)으로 넘어왔을때 jwt 토큰 생성)
			        SecureRandom random = new SecureRandom();
			        byte[] keyBytes = new byte[32]; // 32 bytes = 256 bits
			        random.nextBytes(keyBytes);
			        String secretKey = Base64.getEncoder().encodeToString(keyBytes); //랜덤하게 생성된 크기의 바이트를 임시 시크릿키로 사용
			        
			        byte[] key = Base64.getDecoder().decode(secretKey);
			        
			        String jws = Jwts.builder()
			                .claim("sub", item.getUserId())
			                .signWith(Keys.hmacShaKeyFor(key))
			                .compact();
			        
			    	// 토큰을 쿠키에 저장
			        /* Cookie도 LocalStorage랑 마찬가지로 XSS에 탈취당할 가능성이있음. 하지만 Cookie에는 HttpOnly라는 
			          	옵션이 존재하는데 이 옵션을 지정하면 Script에서 Cookie를 읽어올 수 없게한다. 
			          	이로인해 악의적인 Script에서 Cookie를 가져올 수 없기 때문에 XSS공격에 방어가 된다. */
			        /* localhost 즉 나의 localhost8090 에서 쓰일것이며 모든경로(Path=/)에서 쓰일 것인 jwt 토큰을 쿠키에 저장한다.
			         * 쿠키에 'HttpOnly' 속성을 설정하면 JavaScript에서 쿠키에 접근할 수 없게 됨
			         * 이 속성은 XSS 공격을 방지하는 데 도움이 되지만, 로컬 개발 환경에서는 문제(jwt 토큰이 쿠키에 저장 되지않는 문제 등)를 일으킬 수 있다.
			         */
			        response.setHeader("Set-Cookie", "token=" + jws + "; Domain=localhost; Path=/");
			        
			        /*"token"이라는 이름의 쿠키를 생성하고, 그 값으로 jws를 설정하며, 이 쿠키는 HTTPS 연결에서만 전송되고 클라이언트 측 스크립트에 의한 접근이 차단 하여 XSS를 방어함
			         * 근데 localhost는 http 이므로 Secure; 즉 Secure 가 true 면 HTTPS 전용 쿠키가 설정되기에 쓸 수 없다.(이게 보안에 더 좋음 보통 사이트는 https니까..)
			         
			        	response.setHeader("Set-Cookie", "token=" + jws + "; Secure; HttpOnly");
			        */
			        
			        // CSRF 토큰 생성 및 세션에 저장(소셜 로그인은 화면이 리다이렉트 되기 때문에 소셜 로그인 화면 리다이렉트 이후 내 url(localhost)으로 넘어왔을때 csrf 토큰 생성)
			        //클라이언트에서 요청을 보낼 때 'X-CSRF-TOKEN' 헤더에 이 값을 설정하면, 서버에서는 세션에 저장된 CSRF 토큰과 요청에 담긴 CSRF 토큰이 일치하는지 확인하여 요청의 유효성을 검증할 수 있다.
			        String csrfToken = UUID.randomUUID().toString(); // UUID 클래스를 이용하여 랜덤한 CSRF 토큰을 생성
			        session.setAttribute("CSRF-TOKEN", csrfToken);
			        
					session.setAttribute("user", item);
					
					return "redirect:/";
				}
			}
					
			//네이버 간편 자동 회원가입 처리
			else if(userS.item(item.getUserId()) == null)
			{
				userS.oauthAdd(item);
						
				//자동 회원가입 처리 후 바로 로그인함
				if (userS.oauthLogin(item)) 
				{
					// 토큰 생성(소셜 로그인은 화면이 리다이렉트 되기 때문에 소셜 로그인 화면 리다이렉트 이후 내 url(localhost)으로 넘어왔을때 jwt 토큰 생성)
			        SecureRandom random = new SecureRandom();
			        byte[] keyBytes = new byte[32]; // 32 bytes = 256 bits
			        random.nextBytes(keyBytes);
			        String secretKey = Base64.getEncoder().encodeToString(keyBytes); //랜덤하게 생성된 크기의 바이트를 임시 시크릿키로 사용
			        
			        byte[] key = Base64.getDecoder().decode(secretKey);
			        
			        String jws = Jwts.builder()
			                .claim("sub", item.getUserId())
			                .signWith(Keys.hmacShaKeyFor(key))
			                .compact();
			        
			    	// 토큰을 쿠키에 저장
			        /* Cookie도 LocalStorage랑 마찬가지로 XSS에 탈취당할 가능성이있음. 하지만 Cookie에는 HttpOnly라는 
			          	옵션이 존재하는데 이 옵션을 지정하면 Script에서 Cookie를 읽어올 수 없게한다. 
			          	이로인해 악의적인 Script에서 Cookie를 가져올 수 없기 때문에 XSS공격에 방어가 된다. */
			        /* localhost 즉 나의 localhost8090 에서 쓰일것이며 모든경로(Path=/)에서 쓰일 것인 jwt 토큰을 쿠키에 저장한다.
			         * 쿠키에 'HttpOnly' 속성을 설정하면 JavaScript에서 쿠키에 접근할 수 없게 됨
			         * 이 속성은 XSS 공격을 방지하는 데 도움이 되지만, 로컬 개발 환경에서는 문제(jwt 토큰이 쿠키에 저장 되지않는 문제 등)를 일으킬 수 있다.
			         */
			        response.setHeader("Set-Cookie", "token=" + jws + "; Domain=localhost; Path=/");
			        
			        /*"token"이라는 이름의 쿠키를 생성하고, 그 값으로 jws를 설정하며, 이 쿠키는 HTTPS 연결에서만 전송되고 클라이언트 측 스크립트에 의한 접근이 차단 하여 XSS를 방어함
			         * 근데 localhost는 http 이므로 Secure; 즉 Secure 가 true 면 HTTPS 전용 쿠키가 설정되기에 쓸 수 없다.(이게 보안에 더 좋음 보통 사이트는 https니까..)
			         
			        	response.setHeader("Set-Cookie", "token=" + jws + "; Secure; HttpOnly");
			        */
			        
			        // CSRF 토큰 생성 및 세션에 저장(소셜 로그인은 화면이 리다이렉트 되기 때문에 소셜 로그인 화면 리다이렉트 이후 내 url(localhost)으로 넘어왔을때 csrf 토큰 생성)
			        //클라이언트에서 요청을 보낼 때 'X-CSRF-TOKEN' 헤더에 이 값을 설정하면, 서버에서는 세션에 저장된 CSRF 토큰과 요청에 담긴 CSRF 토큰이 일치하는지 확인하여 요청의 유효성을 검증할 수 있다.
			        String csrfToken = UUID.randomUUID().toString(); // UUID 클래스를 이용하여 랜덤한 CSRF 토큰을 생성
			        session.setAttribute("CSRF-TOKEN", csrfToken);
			       
					session.setAttribute("user", item);
							
					return "redirect:/";
				}
						
				return "redirect:/";
			}
		}
		return "redirect:/";
	}
}
