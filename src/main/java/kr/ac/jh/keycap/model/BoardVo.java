package kr.ac.jh.keycap.model;

import java.util.Date;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class BoardVo {
	
	int boardNum;
	String boardTitle;
	String boardContent;
	String boardImg;
	Date boardDate;
	int boardYn;
	String boardAnswer;
	String userId;
	int keycapNum;
	
	List<KeycapVo> keycap;
	List<UserVo> user;
	
	MultipartFile uploadFile;

	public int getBoardNum() {
		return boardNum;
	}

	public void setBoardNum(int boardNum) {
		this.boardNum = boardNum;
	}
	
	public String getBoardTitle() {
		return boardTitle;
	}

	public void setBoardTitle(String boardTitle) {
		this.boardTitle = boardTitle;
	}

	public String getBoardContent() {
		return boardContent;
	}

	public void setBoardContent(String boardContent) {
		this.boardContent = boardContent;
	}

	public String getBoardImg() {
		return boardImg;
	}

	public void setBoardImg(String boardImg) {
		this.boardImg = boardImg;
	}

	public Date getBoardDate() {
		return boardDate;
	}

	public void setBoardDate(Date boardDate) {
		this.boardDate = boardDate;
	}

	public int getBoardYn() {
		return boardYn;
	}

	public void setBoardYn(int boardYn) {
		this.boardYn = boardYn;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public int getKeycapNum() {
		return keycapNum;
	}

	public void setKeycapNum(int keycapNum) {
		this.keycapNum = keycapNum;
	}

	public List<KeycapVo> getKeycap() {
		return keycap;
	}

	public void setKeycap(List<KeycapVo> keycap) {
		this.keycap = keycap;
	}

	public List<UserVo> getUser() {
		return user;
	}

	public void setUser(List<UserVo> user) {
		this.user = user;
	}

	public MultipartFile getUploadFile() {
		return uploadFile;
	}

	public void setUploadFile(MultipartFile uploadFile) {
		this.uploadFile = uploadFile;
	}

	public String getBoardAnswer() {
		return boardAnswer;
	}

	public void setBoardAnswer(String boardAnswer) {
		this.boardAnswer = boardAnswer;
	}
	
}
