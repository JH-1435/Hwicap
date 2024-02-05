package kr.ac.jh.keycap.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import kr.ac.jh.keycap.dao.AdminDao;
import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.util.Pager;

@Service
public class AdminServiceImpl implements AdminService {

	@Autowired
	AdminDao dao;
	
	@Override
	public List<AdminVo> list(Pager pager) {
		int total = dao.total(pager);
		
		pager.setTotal(total);
		
		return dao.list(pager);
	}

	@Override
	public void add(AdminVo item) {
		dao.add(item);
	}

	@Override
	public AdminVo item(String adminId) {
		return dao.item(adminId);
	}

	@Override
	public void update(AdminVo item) {
		dao.update(item);
	}

	@Override
	public void delete(String adminId) {
		dao.delete(adminId);
	}

	@Override
	public boolean loginAdmin(AdminVo item) {
		AdminVo admin = dao.loginAdmin(item);
		if(admin != null) {
			
			item.setAdminPw(null);
			item.setAdminName(admin.getAdminName() );
			item.setAdminState(admin.getAdminState() );
			
			return true;
		}
		
		return false;
	}
}
