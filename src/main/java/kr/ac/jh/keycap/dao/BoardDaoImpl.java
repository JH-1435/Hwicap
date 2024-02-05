package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.BoardVo;
import kr.ac.jh.keycap.util.Pager;

@Repository
public class BoardDaoImpl implements BoardDao {
	
	@Autowired
	SqlSession sql;
	
	@Override
	public int totalUser(Map<String, Object> list) {
		return sql.selectOne("board.totalUser", list);
	}

	@Override
	public List<BoardVo> listUser(Map<String, Object> list) {
		return sql.selectList("board.listUser", list);
	}

	@Override
	public int total(Map<String, Object> list) {
		return sql.selectOne("board.total", list);
	}

	@Override
	public List<BoardVo> list(Map<String, Object> list) {
		return sql.selectList("board.list", list);
	}

	@Override
	public void add(BoardVo item) {
		sql.insert("board.add", item);
	}

	@Override
	public void update(BoardVo item) {
		sql.update("board.update", item);
	}

	@Override
	public void delete(int boardNum) {
		sql.delete("board.delete", boardNum);
	}

	@Override
	public BoardVo item(int boardNum) {
		return sql.selectOne("board.item", boardNum);
	}

	@Override
	public int totalBoard(int keycapNum) {
		return sql.selectOne("board.totalBoard", keycapNum);
	}

	@Override
	public boolean selectCountInBoard(BoardVo item) throws DataAccessException {
		String result = sql.selectOne("board.selectCountInBoard", item);
		return Boolean.parseBoolean(result);
	}

	@Override
	public int totalAdmin(Pager pager) {
		return sql.selectOne("board.totalAdmin", pager);
	}

	@Override
	public List<BoardVo> listAdmin(Pager pager) {
		return sql.selectList("board.listAdmin", pager);
	}

}
