package kr.ac.jh.keycap.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import kr.ac.jh.keycap.dao.UserDao;
import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.util.Pager;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	UserDao dao;
		
	@Override
	public List<UserVo> list(Pager pager) {
		int total = dao.total(pager);
		
		pager.setTotal(total);
		
		return dao.list(pager);
	}

	@Override
	public void add(UserVo item) {
		dao.add(item);
	}

	@Override
	public UserVo item(String userId) {
		return dao.item(userId);
	}

	@Override
	public void update(UserVo item) {
		dao.update(item);
	}

	@Override
	public void delete(String userId) {
		dao.delete(userId);
	}

	@Override
	public boolean login(UserVo item) {
		UserVo user = dao.login(item);
		if(user != null) {
			
			item.setUserPw(null);
			item.setUserName(user.getUserName() );
			item.setUserAddress(user.getUserAddress() );
			item.setUserTel(user.getUserTel());
			
			return true;
		}
		
		return false;
	}

	@Override
	public void oauthAdd(UserVo item) {
		dao.oauthAdd(item);
	}

	@Override
	public boolean oauthLogin(UserVo item) {
		UserVo user = dao.oauthLogin(item);
		
		if(user != null) {
						
			return true;
		}
		
		return false;
	}
}