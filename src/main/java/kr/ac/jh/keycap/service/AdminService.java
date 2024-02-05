package kr.ac.jh.keycap.service;

import java.util.List;

import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.util.Pager;

//인터페이스를 만드는 이유는 느슨한 결합을 맞추기 위해, 공동작업시 충돌을 방지 하기 위해서 이다.
public interface AdminService {

	List<AdminVo> list(Pager pager);

	void add(AdminVo item);

	AdminVo item(String adminId);

	void update(AdminVo item);

	void delete(String adminId);
	
	boolean loginAdmin(AdminVo item);

}
