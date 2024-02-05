package kr.ac.jh.keycap.controller;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Safelist;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.model.BoardVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.service.BoardService;
import kr.ac.jh.keycap.service.KeycapService;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/board")
public class BoardController {
final String path = "board/";
final String uploadPath = "D:/HwicapUpload/userImgF/"; 

	@Autowired
	BoardService service;
	
	@Autowired
	KeycapService serviceKeycap;
	
	//Date 형식을 스프링에게 어떤값으로 변환될지 알려줌
	@InitBinder
	private void dataBinder(WebDataBinder binder) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
					
		CustomDateEditor editor = new CustomDateEditor(dateFormat, true);
					
		binder.registerCustomEditor(Date.class, editor);
	}
	
	// 관리자가 전체 QnA 보기
	@GetMapping("/listAdmin")
	String list(Model model, Pager pager) {
		List<BoardVo> list = service.listAdmin(pager);
			
		/* JSoup 라이브러리를 이용하여 안전한 HTML만을 허용하는 처리
	     * CKEditor에서는 줄바꿈을 <p> 태그로 처리하므로, 이 변경은 필요 없을 수도 있음. 
	     * 만약 \n을 <br>로 변경하는 기능이 필요하다면, Jsoup.clean() 메서드를 호출하기 전에 변경하면 됨 */
		for (BoardVo board : list) {
	        String contentBoard = board.getBoardContent();
	        contentBoard = Jsoup.clean(contentBoard, Safelist.basic()); // Jsoup.clean() 메소드는 입력된 HTML 문자열을 안전하게 만들어주며, Safelist.basic()는 기본적으로 안전한 HTML 태그만을 허용하는 설정 
	        board.setBoardContent(contentBoard);
	    }
		
		model.addAttribute("list", list);
			
		return path + "listAdmin";
	}
	//회원 각각의 QnA내역 보기
	@GetMapping("/{userId}/list")
	String list(@PathVariable("userId") String userId, Model model, Pager pager) {
					
		List<BoardVo> list = service.listUser(userId, pager);
		
		/* JSoup 라이브러리를 이용하여 안전한 HTML만을 허용하는 처리
	     * CKEditor에서는 줄바꿈을 <p> 태그로 처리하므로, 이 변경은 필요 없을 수도 있음. 
	     * 만약 \n을 <br>로 변경하는 기능이 필요하다면, Jsoup.clean() 메서드를 호출하기 전에 변경하면 됨 */
		for (BoardVo board : list) {
	        String contentBoard = board.getBoardContent();
	        contentBoard = Jsoup.clean(contentBoard, Safelist.basic()); // Jsoup.clean() 메소드는 입력된 HTML 문자열을 안전하게 만들어주며, Safelist.basic()는 기본적으로 안전한 HTML 태그만을 허용하는 설정 
	        board.setBoardContent(contentBoard);
	    }
					
		model.addAttribute("list", list);
					
		return path + "list";
	}
	
	//이미지 중복 처리(다른 컨트롤러 메서드 내에서 호출되어 사용되므로, 별도로 @GetMapping 또는 @PostMapping 어노테이션을 사용하여 HTTP 요청에 바로 매핑할 필요가 없음)
	public String handleUpload(MultipartFile file) throws IOException {
	    String filename = file.getOriginalFilename();
	    Path filePath = Paths.get(uploadPath, filename);
	    
	    // URL 디코딩(저장되는 파일에 한국어가 있으면 인코딩된 #E@RE# 이런식으로 보이기 때문에 디코딩 한다.)
	    String decodedFilename = URLDecoder.decode(filename, StandardCharsets.UTF_8.toString());
	    
	    // 이미 파일이 존재할 경우 삭제
	    if (Files.exists(filePath)) {
	        Files.delete(filePath);
	    }

	    file.transferTo(filePath.toFile()); //파일 복사
	    
	    return "/images/" + decodedFilename; // 클라이언트에서 접근 가능한 이미지 URL
	}
	
	/* upload 처리,  CKEditor의 SimpleUploadAdapter 플러그인이 이미지 업로드를 위해 서버에 보내는 요청의 형식인데 
 	SimpleUploadAdapter는 이미지를 'upload'라는 이름의 multipart/form-data 형식의 요청 본문에 포함하여 보냄
	따라서 서버에서는 @RequestParam("upload") MultipartFile file 형식으로 요청 본문에서 이미지를 받아야 함.
	하지만 CKEditor의 SimpleUploadAdapter는 'upload'라는 이름으로 이미지를 보내는 것이 기본 설정이며, 이를 변경하는 것은 공식적으로 지원되지 않는다.
	 */
	@PostMapping("/uploadImage")
	@ResponseBody
	public ResponseEntity<Map<String, Object>> uploadImage(@RequestParam("upload") MultipartFile[] files, HttpSession session) {
	    Map<String, Object> response = new HashMap<>();
	    try {
	        String url = null;
	        for(MultipartFile file : files) {
	            if(file != null && !file.isEmpty()) {
	                url = handleUpload(file);
	            }
	        }
	        response.put("uploaded", "true");
	        response.put("url", url); // 마지막으로 업로드된 이미지의 URL
	    } catch (IOException e) {
	        e.printStackTrace();
	        response.put("uploaded", "false");
	        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
	    }
	    
	    return new ResponseEntity<>(response, HttpStatus.OK);
	}
	
	// QnA 등록	
	@GetMapping("/{keycapNum}/add")
	String add(@PathVariable int keycapNum, Model model) {
		KeycapVo keycap = serviceKeycap.item(keycapNum); 
		model.addAttribute("keycap", keycap);
		
		return path + "add";
	}
	
	@PostMapping("/{keycapNum}/add")
	public String add(BoardVo item, @PathVariable("keycapNum") int keycapNum, HttpSession session) {
	    UserVo user = (UserVo) session.getAttribute("user");
	    try {
	        if(user != null) {
	            // QnA 내용에서 이미지 URL을 추출
	            Document doc = Jsoup.parse(item.getBoardContent());
	            Elements imgElements = doc.select("img");
	            
	            // 리뷰에 이미지가 없는 경우
	            if (imgElements.isEmpty()) {
	                // BoardImg를 null로 설정
	                item.setBoardImg(null);
	            } else {
	                // 모든 이미지의 URL을 저장할 문자열 생성
	                StringBuilder imgUrls = new StringBuilder();

	                for (Element img : imgElements) {
	                    String imgUrl = img.attr("src");
	                    // 이미지 URL을 문자열에 추가
	                    if (imgUrls.length() > 0) {
	                        imgUrls.append(";");
	                    }
	                    imgUrls.append(imgUrl);
	                }
	                // 모든 이미지 URL을 BoardVo에 저장
	                item.setBoardImg(imgUrls.toString());
	            } 
	            item.setUserId(user.getUserId());
	            service.add(item); //add를 호출하여 item 저장
	        }
	    } catch (IllegalStateException e) {
	        e.printStackTrace();
	    }

	    return "redirect:../" + user.getUserId() + "/" + "list";
	}
	
	// 1:1 QnA 등록	
	@GetMapping("/{userId}/addCs")
	String addCs(@PathVariable String userId) {			
		return path + "addCs";
	}
		
	@PostMapping("/{userId}/addCs")
	public String addCs(BoardVo item, @PathVariable("userId") String userId, HttpSession session) {
		   UserVo user = (UserVo) session.getAttribute("user");
		   try {
		       if(user != null) {
		           // QnA 내용에서 이미지 URL을 추출
		           Document doc = Jsoup.parse(item.getBoardContent());
		           Elements imgElements = doc.select("img");
		            
		           // 리뷰에 이미지가 없는 경우
		           if (imgElements.isEmpty()) {
		               // BoardImg를 null로 설정
		               item.setBoardImg(null);
		           } else {
		               // 모든 이미지의 URL을 저장할 문자열 생성
		               StringBuilder imgUrls = new StringBuilder();

		               for (Element img : imgElements) {
		                   String imgUrl = img.attr("src");
		                   // 이미지 URL을 문자열에 추가
		                   if (imgUrls.length() > 0) {
		                       imgUrls.append(";");
		                   }
		                   imgUrls.append(imgUrl);
		               }
		               // 모든 이미지 URL을 BoardVo에 저장
		               item.setBoardImg(imgUrls.toString());
		           } 
		           item.setUserId(user.getUserId());
		           item.setKeycapNum(0);
		           service.add(item); //add를 호출하여 item 저장
		       }
		   } catch (IllegalStateException e) {
		       e.printStackTrace();
		   }

		   return "redirect:../" + user.getUserId() + "/" + "list";
	}
	
	//QnA 답변 (관리자전용)
	@GetMapping("/{BoardNum}/update")
	String update(@PathVariable int BoardNum, Model model) {
		BoardVo item = service.item(BoardNum);
		KeycapVo keycap = serviceKeycap.item(item.getKeycapNum());
		
		model.addAttribute("item", item);
		model.addAttribute("keycap", keycap);
		
		return path + "update";
	}
	
	//QnA 답변 (관리자전용)
	@PostMapping("/{BoardNum}/update")
	String update(@PathVariable int BoardNum, BoardVo item) {
		item.setBoardYn(1);
		
		service.update(item);
		
		return "redirect:../" + "listAdmin";
	}		
	
	//QnA삭제
	@GetMapping("/{BoardNum}/delete")
	String delete(@PathVariable int boardNum, HttpSession session) {
		UserVo user = (UserVo) session.getAttribute("user");
		service.delete(boardNum);
			
		return "redirect:../" + user.getUserId() + "/" + "list";
	}
}
