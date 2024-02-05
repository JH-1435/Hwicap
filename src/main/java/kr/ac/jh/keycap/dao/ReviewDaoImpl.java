package kr.ac.jh.keycap.dao;

import java.util.List;

import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.ReviewVo;

@Repository
public class ReviewDaoImpl implements ReviewDao {

	@Autowired
	SqlSession sql;
	
	@Override
	public int total(Map<String, Object> list) {
		return sql.selectOne("review.total", list);
	}

	@Override
	public List<ReviewVo> list(Map<String, Object> list) {
		return sql.selectList("review.list", list);
	}

	@Override
	public int totalUser(Map<String, Object> list) {
		return sql.selectOne("review.totalUser", list);
	}

	@Override
	public List<ReviewVo> listUser(Map<String, Object> list) {
		return sql.selectList("review.listUser", list);
	}

	@Override
	public ReviewVo item(int reviewNum) {
		return sql.selectOne("review.item", reviewNum);
	}

	@Override
	public void update(ReviewVo item) {
		sql.update("review.update", item);
	}

	@Override
	public void delete(int reviewNum) {
		sql.delete("review.delete", reviewNum);
	}

	@Override
	public void add(ReviewVo item) {
		sql.insert("review.add", item);
	}

	@Override
	public int totalReview(int keycapNum) {
		return sql.selectOne("review.totalReview", keycapNum);
	}

}
