package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.ReviewVo;

public interface ReviewDao {

	int total(Map<String, Object> list);

	List<ReviewVo> list(Map<String, Object> list);

	int totalUser(Map<String, Object> list);

	List<ReviewVo> listUser(Map<String, Object> list);

	ReviewVo item(int reviewNum);

	void update(ReviewVo item);

	void delete(int reviewNum);

	void add(ReviewVo item);

	int totalReview(int keycapNum);
	
}
