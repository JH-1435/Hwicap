package kr.ac.jh.keycap.dao;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.util.Pager;

@Repository
public class AdminDaoImpl implements AdminDao {

	@Autowired
	SqlSession sql;
	
	@Override
	public List<AdminVo> list(Pager pager) {
		return sql.selectList("admin.list", pager);
	}

	@Override
	public void add(AdminVo item) {
		sql.insert("admin.add", item);
	}

	@Override
	public AdminVo item(String adminId) {
		return sql.selectOne("admin.item", adminId);
	}

	@Override
	public void update(AdminVo item) {
		sql.update("admin.update", item);
	}

	@Override
	public void delete(String adminId) {
		sql.delete("admin.delete", adminId);
	}

	@Override
	public AdminVo loginAdmin(AdminVo item) {
		return sql.selectOne("admin.login", item);
	}
	@Override
	public int total(Pager pager) {
		return sql.selectOne("admin.total", pager);
	}
	

}
