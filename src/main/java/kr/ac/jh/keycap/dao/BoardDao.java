package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.BoardVo;
import kr.ac.jh.keycap.util.Pager;

public interface BoardDao {

	int totalUser(Map<String, Object> list);

	List<BoardVo> listUser(Map<String, Object> list);

	int total(Map<String, Object> list);

	List<BoardVo> list(Map<String, Object> list);

	void add(BoardVo item);

	void update(BoardVo item);

	void delete(int boardNum);

	BoardVo item(int boardNum);

	int totalBoard(int keycapNum);

	boolean selectCountInBoard(BoardVo item);

	int totalAdmin(Pager pager);

	List<BoardVo> listAdmin(Pager pager);
	
}
