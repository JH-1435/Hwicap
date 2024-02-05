package kr.ac.jh.keycap.service;

import java.util.List;

import kr.ac.jh.keycap.model.ReviewVo;
import kr.ac.jh.keycap.util.Pager;

public interface ReviewService {

	List<ReviewVo> list(int keycapNum, Pager pager);

	List<ReviewVo> listUser(String userId, Pager pager);

	ReviewVo item(int reviewNum);
	
	void update(ReviewVo item);

	void delete(int reviewNum);

	void add(ReviewVo item);

	int totalReview(int keycapNum);
}
