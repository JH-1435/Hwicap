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

import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.model.ReviewVo;
import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.service.OrdersService;
import kr.ac.jh.keycap.service.ReviewService;
import kr.ac.jh.keycap.service.UserService;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/review")
public class ReviewController {
final String path = "review/";
final String uploadPath = "D:/HwicapUpload/userImgF/"; 

	@Autowired
	ReviewService service;
	
	@Autowired
	OrdersService serviceOrders;
	
	@Autowired
	UserService serviceUser;
	
	//Date 형식을 스프링에게 어떤값으로 변환될지 알려줌
	@InitBinder
	private void dataBinder(WebDataBinder binder) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
					
		CustomDateEditor editor = new CustomDateEditor(dateFormat, true);
					
		binder.registerCustomEditor(Date.class, editor);
	}
	
	/* 관리자가 전체 리뷰 보기 -- 보류 --
	@GetMapping("/listAdmin")
	String list(Model model, Pager pager) {
		List<ReviewVo> list = service.list(pager);
			
		model.addAttribute("list", list);
			
		return path + "listAdmin";
	}
	*/
	
	//회원 각각의 리뷰내역 보기
	@GetMapping("/{userId}/list")
	String list(@PathVariable("userId") String userId, Model model, Pager pager) {
					
		List<ReviewVo> list = service.listUser(userId, pager);
		
		/* JSoup 라이브러리를 이용하여 안전한 HTML만을 허용하는 처리
	     * CKEditor에서는 줄바꿈을 <p> 태그로 처리하므로, 이 변경은 필요 없을 수도 있음. 
	     * 만약 \n을 <br>로 변경하는 기능이 필요하다면, Jsoup.clean() 메서드를 호출하기 전에 변경하면 됨 */
	    for (ReviewVo review : list) {
	        String content = review.getReviewContent();
	        content = Jsoup.clean(content, Safelist.basic()); // Jsoup.clean() 메소드는 입력된 HTML 문자열을 안전하게 만들어주며, Safelist.basic()는 기본적으로 안전한 HTML 태그만을 허용하는 설정 
	        review.setReviewContent(content);
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
	
	// 리뷰 등록	
	@GetMapping("/{orderSeqNum}/add")
	String add(@PathVariable int orderSeqNum, Model model) {
		OrdersVo orders = serviceOrders.item(orderSeqNum); 
		model.addAttribute("orders", orders);
		
		return path + "add";
	}
	
	@PostMapping("/{orderSeqNum}/add")
	public String add(ReviewVo item, @PathVariable("orderSeqNum") int orderSeqNum, HttpSession session) {
	    UserVo user = (UserVo) session.getAttribute("user");
	    try {
	        if(user != null) {
	            // 리뷰 내용에서 이미지 URL을 추출
	            Document doc = Jsoup.parse(item.getReviewContent());
	            Elements imgElements = doc.select("img");
	            
	            // 리뷰에 이미지가 없는 경우
	            if (imgElements.isEmpty()) {
	                // ReviewImg를 null로 설정
	                item.setReviewImg(null);
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
	                // 모든 이미지 URL을 ReviewVo에 저장
	                item.setReviewImg(imgUrls.toString());
	            } 
	            item.setUserId(user.getUserId());
	            service.add(item); //add를 호출하여 item 저장
	        }
	    } catch (IllegalStateException e) {
	        e.printStackTrace();
	    }

	    return "redirect:../" + user.getUserId() + "/" + "list";
	}
	
	//리뷰 수정
	@GetMapping("/{reviewNum}/update")
	String update(@PathVariable int reviewNum, Model model) {
		ReviewVo item = service.item(reviewNum);
			
		model.addAttribute("item", item);
			
		return path + "update";
	}
	
	///update 엔드포인트를 수정하여 세션에서 이미지 경로 문자열을 가져온 후, 세미콜론으로 분리하여 이미지 경로 리스트를 만든다.
	@PostMapping("/{reviewNum}/update")
	String update(@PathVariable int reviewNum, ReviewVo item, HttpSession session) {
	    UserVo user = (UserVo) session.getAttribute("user");
	    try {
	        if(user != null) {
	            // 리뷰 내용에서 이미지 URL을 추출
	            Document doc = Jsoup.parse(item.getReviewContent());
	            Elements imgElements = doc.select("img");
	            
	            // 리뷰에 이미지가 없는 경우
	            if (imgElements.isEmpty()) {
	                // ReviewImg를 null로 설정
	                item.setReviewImg(null);
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
	                // 모든 이미지 URL을 ReviewVo에 저장
	                item.setReviewImg(imgUrls.toString());
	            } 
	            item.setReviewNum(reviewNum);
	    	    service.update(item);
	        }
	    } catch (IllegalStateException e) {
	        e.printStackTrace();
	    }
	    return "redirect:../" + user.getUserId() + "/" + "list";
	}
		
	//리뷰삭제
	@GetMapping("/{reviewNum}/delete")
	String delete(@PathVariable int reviewNum, HttpSession session) {
		UserVo user = (UserVo) session.getAttribute("user");
		service.delete(reviewNum);
			
		return "redirect:../" + user.getUserId() + "/" + "list";
	}
}
