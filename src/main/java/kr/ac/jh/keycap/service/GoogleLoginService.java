package kr.ac.jh.keycap.service;

import java.util.HashMap;

public interface GoogleLoginService {
	//받아온 구code 담음
	String getAccessToken(String authorize_code);

	public HashMap<String, Object> getUserInfo(String access_Token);
}
