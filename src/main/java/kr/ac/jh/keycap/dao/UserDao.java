package kr.ac.jh.keycap.dao;

import java.util.List;

import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.util.Pager;

//인터페이스를 만드는 이유는 느슨한 결합을 맞추기 위해, 공동작업시 충돌을 방지 하기 위해서 이다.
public interface UserDao {

	List<UserVo> list(Pager pager);

	void add(UserVo item);

	UserVo item(String userId);

	void update(UserVo item);

	void delete(String userId);

	UserVo login(UserVo item);

	int total(Pager pager);

	void oauthAdd(UserVo item);

	UserVo oauthLogin(UserVo item);
	
}
