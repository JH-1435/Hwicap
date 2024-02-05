package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.HeartVo;

@Repository
public class HeartDaoImpl implements HeartDao {

	@Autowired
	SqlSession sql;
	
	@Override
	public boolean selectCountInHeart(HeartVo item) throws DataAccessException {
		String result = sql.selectOne("heart.selectCountInHeart", item);
		return Boolean.parseBoolean(result);
	}
	
	@Override
	public void add(HeartVo item) throws DataAccessException {
		sql.insert("heart.add", item);
	}

	@Override
	public void delete(HeartVo item) throws DataAccessException {
		sql.delete("heart.delete", item);
	}

	@Override
	public int total(Map<String, Object> list) {
		return sql.selectOne("heart.total", list);
	}

	@Override
	public List<HeartVo> list(Map<String, Object> list) {
		return sql.selectList("heart.list", list);
	}
}
