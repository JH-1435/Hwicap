package kr.ac.jh.keycap.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import kr.ac.jh.keycap.dao.BoardDao;
import kr.ac.jh.keycap.model.BoardVo;
import kr.ac.jh.keycap.util.Pager;

@Service
public class BoardServiceImpl implements BoardService {
	
	@Autowired
	BoardDao dao;
	
	@Override
	public List<BoardVo> listUser(String userId, Pager pager) {
		Map<String, Object> list = new HashMap<String, Object>();
		list.put("userId", userId);
		list.put("pager",  pager);
		
		int total = dao.totalUser(list);
		pager.setTotal(total);
		
		return dao.listUser(list);
	}

	@Override
	public void add(BoardVo item) {
		dao.add(item);
	}

	@Override
	public void update(BoardVo item) {
		dao.update(item);
	}

	@Override
	public void delete(int boardNum) {
		dao.delete(boardNum);
	}

	@Override
	public BoardVo item(int boardNum) {
		return dao.item(boardNum);
	}

	@Override
	public List<BoardVo> list(int keycapNum, Pager pager) {
		Map<String, Object> list = new HashMap<String, Object>();
		list.put("keycapNum", keycapNum);
		list.put("pager",  pager);
		
		int total = dao.total(list);
		pager.setTotal(total);
		
		return dao.list(list);
	}

	@Override
	public int totalBoard(int keycapNum) {
		return dao.totalBoard(keycapNum);
	}

	@Override
	public boolean findBoardNum(BoardVo item) throws Exception {
		return dao.selectCountInBoard(item);
	}

	@Override
	public List<BoardVo> listAdmin(Pager pager) {
		int total = dao.totalAdmin(pager);
		pager.setTotal(total);
		return dao.listAdmin(pager);
	}

}
