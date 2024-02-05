package kr.ac.jh.keycap.dao;

import java.util.List;


import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.util.Pager;

@Repository
public class KeycapDaoImpl implements KeycapDao {

	@Autowired
	SqlSession sql;
	
	@Override
	public List<KeycapVo> list(Pager pager) {
		return sql.selectList("keycap.list", pager);
	}
	
	@Override
	public void add(KeycapVo item) {
		sql.insert("keycap.add", item);
	}

	@Override
	public KeycapVo item(int keycapNum) {
		return sql.selectOne("keycap.item", keycapNum);
	}

	@Override
	public void update(KeycapVo item) {
		sql.update("keycap.update", item);
	}

	@Override
	public void delete(int keycapNum) {
		sql.delete("keycap.delete", keycapNum);
	}

	@Override
	public void keycapReadCount(int keycapNum) {
		sql.update("keycap.keycapReadCount", keycapNum);
	}
	
	@Override
	public int total(Pager pager) {
		return sql.selectOne("keycap.total", pager);
	}
		
	@Override
	public void keycapLike(HeartVo item) throws DataAccessException {
		sql.update("keycap.keycapLike", item);
	}

	@Override
	public void keycapLikeMa(HeartVo item) throws DataAccessException {
		sql.update("keycap.keycapLikeMa", item);
	}
	
	@Override
	public void updateKeycapStock(KeycapVo keycap) {
		sql.update("keycap.keycapOrderStock", keycap);
		
	}

	@Override
	public void updateKeycapOrder(KeycapVo keycap) {
		sql.update("keycap.keycapOrder", keycap);
	}

	@Override
	public List<KeycapVo> listBest(Pager pager) {
		return sql.selectList("keycap.listBest", pager);
	}

	@Override
	public List<KeycapVo> listPriceDesc(Pager pager) {
		return sql.selectList("keycap.listPriceDesc", pager);
	}

	@Override
	public List<KeycapVo> listPriceAsc(Pager pager) {
		return sql.selectList("keycap.listPriceAsc", pager);
	}

	@Override
	public List<KeycapVo> listReviewDesc(Pager pager) {
		return sql.selectList("keycap.listReviewDesc", pager);
	}

}
