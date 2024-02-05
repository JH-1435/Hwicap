package kr.ac.jh.keycap.service;

import java.util.List;

import kr.ac.jh.keycap.model.BoardVo;
import kr.ac.jh.keycap.util.Pager;

public interface BoardService {

	List<BoardVo> listUser(String userId, Pager pager);

	void add(BoardVo item);

	void update(BoardVo item);

	void delete(int boardNum);

	BoardVo item(int boardNum);

	List<BoardVo> list(int keycapNum, Pager pager);

	int totalBoard(int keycapNum);

	boolean findBoardNum(BoardVo item) throws Exception;

	List<BoardVo> listAdmin(Pager pager);
}
