package kr.ac.jh.keycap.controller;

import java.io.File;
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
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

import kr.ac.jh.keycap.service.BoardService;
import kr.ac.jh.keycap.service.CartService;
import kr.ac.jh.keycap.service.HeartService;
import kr.ac.jh.keycap.service.KeycapService;
import kr.ac.jh.keycap.service.OrdersService;
import kr.ac.jh.keycap.service.ReviewService;
import kr.ac.jh.keycap.service.UserService;
import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.model.BoardVo;
import kr.ac.jh.keycap.model.CartVo;
import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.ReviewVo;
import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/keycap")
public class KeycapController {
	final String path = "keycap/";
	final String uploadPath1 = "//d:/HwicapUpload/";
	final String uploadPath2 = "D:/HwicapUpload/keycapImgF/"; 
	
	@Autowired
	KeycapService service;	
		
	@Autowired
	OrdersService serviceOrders;
	
	@Autowired
	CartService serviceCart;
	
	@Autowired
	ReviewService serviceReview;
	
	@Autowired
	BoardService serviceBoard;
	
	@Autowired
	UserService serviceUser;
	
	@Autowired
	HeartService serviceHeart;
	
		// view와 조회수
		@GetMapping("/{keycapNum}/keycapView")
		String view(@PathVariable int keycapNum, Model model, Pager pager) {
			KeycapVo item = service.item(keycapNum);
			pager.setPerPage(20); // 페이지 당 20개씩 보이기
			List<ReviewVo> listReview = serviceReview.list(keycapNum, pager);
			int reviewTotal = serviceReview.totalReview(keycapNum);
			List<BoardVo> listBoard = serviceBoard.list(keycapNum, pager);
			int boardTotal = serviceBoard.totalBoard(keycapNum);
			
			
			 // 별점의 합계를 계산.
		    double totalStar = 0;
		    for (ReviewVo review : listReview) {
		        totalStar += review.getReviewStar();
		    }
		    /* JSoup 라이브러리를 이용하여 안전한 HTML만을 허용하는 처리
		     * CKEditor에서는 줄바꿈을 <p> 태그로 처리하므로, 이 변경은 필요 없을 수도 있음. 
		     * 만약 \n을 <br>로 변경하는 기능이 필요하다면, Jsoup.clean() 메서드를 호출하기 전에 변경하면 됨 */
		    for (ReviewVo review : listReview) {
		        String content = review.getReviewContent();
		        content = Jsoup.clean(content, Safelist.basic()); // Jsoup.clean() 메소드는 입력된 HTML 문자열을 안전하게 만들어주며, Safelist.basic()는 기본적으로 안전한 HTML 태그만을 허용하는 설정 
		        review.setReviewContent(content);
		    }
		    for (BoardVo board : listBoard) {
		        String contentBoard = board.getBoardContent();
		        contentBoard = Jsoup.clean(contentBoard, Safelist.basic()); // Jsoup.clean() 메소드는 입력된 HTML 문자열을 안전하게 만들어주며, Safelist.basic()는 기본적으로 안전한 HTML 태그만을 허용하는 설정 
		        board.setBoardContent(contentBoard);
		    }
		    
		    // 별점의 평균을 계산.
		    double averageStar = (listReview.size() > 0) ? totalStar / listReview.size() : 0;
		    
		    //userId가  'Naver_', 'Google_', 'Kakao_'로 시작하는 모든 사용자의 이름의 userName을 호출하고 userName을 Array배열에 담는다.
		    List<UserVo> userList = serviceUser.list(pager);
		    Map<String, String> userNames = new HashMap<>();
		    for (UserVo user : userList) {
		        String displayName = user.getUserId();
		        boolean isUserId = true; // displayName이 userId인지 확인하는 flag
		        if (user.getUserId().startsWith("Naver_")
		                || user.getUserId().startsWith("Google_")
		                || user.getUserId().startsWith("Kakao_")) {
		            displayName = user.getUserName();
		            isUserId = false;
		        }
		        
		        // displayName에 적응된게 userId라면 앞 3글자만 보이고 나머지는 '*' 처리
		        String maskedDisplayName;
		        if (isUserId) {
		        	maskedDisplayName = displayName.substring(0, 3) 
		                    + displayName.substring(3).replaceAll(".", "*");
		        // displayName에 적용된게 userId 라면 중간값만 '*'로 대체, 한글자면 뒷값만 '*' 함 
		        } else {
		            if (displayName.length() <= 2) {
		                maskedDisplayName = displayName.substring(0, 1) + "*";
		            } else {
		                int mid = displayName.length() / 2;
		                maskedDisplayName = displayName.substring(0, mid)
		                        + "*"  
		                        + displayName.substring(mid + 1);
		            }
		        }
		        
		        //jsp에서 list.userId와 user.getUserId()가 일치하는지 확인
		        userNames.put(user.getUserId(), maskedDisplayName);
		    }
		    
			model.addAttribute("item", item);
			model.addAttribute("listReview", listReview); // 리뷰
			model.addAttribute("averageStar", averageStar);  // 평균 별점을 모델에 추가.
			model.addAttribute("reviewTotal", reviewTotal); // 상품에 따른 리뷰 수 를 모델에 추가.
			model.addAttribute("userNames", userNames); // 소셜 로그인 이용자 들은 userNames으로 보이게 모델에 추가
			model.addAttribute("listBoard", listBoard); // QnA
			model.addAttribute("boardTotal", boardTotal); // 상품에 따른 QnA 수 를 모델에 추가.
			service.keycapReadCount(keycapNum);
						
			return path + "keycapView";
		}
		
		// 게시글 번호 에 따른 유저 체크
		@GetMapping("/checkUser")
		String checkUser() {
			return path + "checkUser";
		}
		
		// 게시글 번호 에 따른 유저 체크
		@PostMapping("/checkBoardUser")
		@ResponseBody
		String checkBoardUser(BoardVo item, HttpSession session,
				@RequestParam("boardNum") int boardNum)
				throws Exception {
			UserVo user = (UserVo) session.getAttribute("user");
			AdminVo admin = (AdminVo) session.getAttribute("admin");
			
			if(user != null ||	admin != null)
			{
				if(admin != null)
				{
					return "user_true";
				}
				
				item.setBoardNum(boardNum);
				item.setUserId(user.getUserId());
				
				boolean isAreadyExisted = serviceBoard.findBoardNum(item);
				
				if(isAreadyExisted == true)
				{
					return "user_true";
				}
				else
				{					
					return "user_false";
				}
			}
			else
			{				
				return "lougout_user";
			}	
		}
		
		// KeycapServiceImpl 에서 dummy 와 init 에 대한 실제로 처리하는 역할을함
		@GetMapping("/dummy")
		String dummy() {
				service.dummy();
			return "redirect:list";
		}
			
		@GetMapping("/init")
		String init() {
			service.init();
			return "redirect:list";
		}
		
		//Date 형식을 스프링에게 어떤값으로 변환될지 알려줌
		@InitBinder
		private void dataBinder(WebDataBinder binder) {
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
			
			CustomDateEditor editor = new CustomDateEditor(dateFormat, true);
			
			binder.registerCustomEditor(Date.class, editor);
		}
		
		/* orders(주문)을 클릭하면,@RequestParam 로 submit한 name을 불러옴
		  UserVo에 있는 데이터를 user라는 세션에 값을 저장함, Map을 content에 주고 "content"라는 변수 로
		   값이 세션에 저장 content의 값이 없으면, content를 초기화 시킴. 여태 모든 값을 service에 전달하여 처리 한후
		   content(세션 값)를 다시 초기화 시킴	*/
		@GetMapping("/orders")
		@ResponseBody
		String order(@RequestParam int cartCount, 
				@RequestParam int total,
				@RequestParam int keycapNum,
				@RequestParam String orderImg,
				@RequestParam String orderUserName,
				@RequestParam String orderTel,
				@RequestParam String orderCall,
				@RequestParam String orderAddress,
				@RequestParam String orderAddress_postcode,
				@RequestParam String orderAddress_detailAddress,
				@RequestParam String orderMsg,
				@RequestParam String orderPay,
				@RequestParam String orderCard,
				@RequestParam int orderCardPlan,
				@RequestParam String orderTelPlan,
				HttpSession session) throws Exception {
			
			UserVo user = (UserVo) session.getAttribute("user");
			String orderAddress_final = "[" + orderAddress_postcode + "]" + " " +orderAddress + " " +orderAddress_detailAddress;
			KeycapVo itemKeycap = service.item(keycapNum);
			
			//상품주문 처리
			@SuppressWarnings("unchecked")
			Map<Integer, KeycapVo> content = (Map<Integer, KeycapVo>) session.getAttribute("content");
			if(content == null || content.isEmpty()) {
				return "redirect:/";
			}
			
			//결제 중 상품이 하나라도 픔절 이면 결제 취소 or 주문수량이 상품수량보다 많으면 결제취소
			if(itemKeycap.getKeycapStock() < 1) {
				return "ordersError";
			} else if(itemKeycap.getKeycapStock() < cartCount) {
				return "ordersErrorTotal";
			}
			
			serviceOrders.order(user.getUserId(), user.getUserName(), user.getUserTel(), user.getUserAddress(), 
					cartCount, total, orderImg, orderUserName, orderTel, orderCall, orderAddress_final, orderMsg, orderPay,
					orderCard, orderCardPlan, orderTelPlan, content);
			
			//장바구니 중복 삭제
			List<CartVo> cartList = serviceCart.list(user.getUserId());
			for(int index = 0; index < cartList.size(); index++)
			{
				CartVo userCartNum =  cartList.get(index);
				CartVo item = serviceCart.item(userCartNum);
								
				for(int keycapNumKey : content.keySet())
				{
					KeycapVo keycap = content.get(keycapNumKey);
					
					if(keycap.getKeycapNum() == item.getKeycapNum())
					{
						serviceCart.delete(item.getCartNum());
					}
					
				}
			}
			
			content.clear();
			
			return "redirect:/keycap/list?sort=null";
		}
		
		//상품 선택 하여 content페이지로 오면 선택했던 상품정보를  Map 가상인터페이스 에 담음 => HashMap이 실행하여 동작
		// 인터페이스 와 클래스(Impl)같은 관계
		// Map은 inteferface로서 key, value 조합을 사용하는 데이터형의 껍데기
		// HashMap은 Hash key 기반의 map을 이미 구현한 클래스
			@RequestMapping("/content")
			String content(@RequestParam int keycapNum, @RequestParam int cartCount,
					@RequestParam int total,
					Model model, HttpSession session) {
				if(keycapNum != 0) {
					KeycapVo item = service.item(keycapNum);
					
					//서버로 넘어온 값을 모달을 이용하여 다른 jsp에서  호출할 수 있음 (즉 ajax, form 등으로 받은 데이터를 다른 jsp에 호출하기 위함)${cartCount} , ${total} 등으로 이용할 수 있음.
					 model.addAttribute("cartCount", cartCount);
					 model.addAttribute("total", total);
					
					@SuppressWarnings("unchecked")
					Map<Integer, KeycapVo> content = (Map<Integer, KeycapVo>) session.getAttribute("content");
					if(content == null) {
						content = new HashMap<Integer, KeycapVo>();
						
						session.setAttribute("content", content);
					} else {
						content.clear(); //구매하기는 하나에 한 아이템만 담아서 넘기므로 만약 content 세션에 이미 값이(기존 사용자가 구매하기 누르고 뒤로가기 누른경우) 있다면 세션을 비움
					}
					
					content.put(keycapNum, item);
				}	
				
				return path + "content";
			}
			
			//content 라는 세션데이터만 삭제, required = false << 파라미터값 필수값아님. 즉 파라미터값이 없으면 null로 됨
			@GetMapping("/contentInit")
			@ResponseBody
			String content(HttpSession session, 
					@RequestParam(required = false) String name) {
				
				session.removeAttribute("content");
				
				if(name != null)
				{
					return "redirect:/";
				}
				else
				{
					return "redirect:/keycap/list";
				}
			}
						
		//상품 찜하기
		@GetMapping("/heart")
		String heart() {
			return path + "heart";
		}
		
		//상품 찜하기
		@PostMapping("/heart")
		@ResponseBody
		String heart(HeartVo item, HttpSession session,
				@RequestParam("keycapNum") int keycapNum,
				@RequestParam("heartTry") int heartTry)
				throws Exception {
			
			UserVo user = (UserVo) session.getAttribute("user");
			if(user != null)
			{
				item.setKeycapNum(keycapNum);
				item.setUserId(user.getUserId());
				
				//찜하기 구분
				boolean isAreadyExisted = service.findHeartKeycapNum(item);
				
				//이미 찜 했다면 true 아니면 false
				if(isAreadyExisted == true)
				{
					if(heartTry > 0)
					{
						service.keycapLikeMa(item);
						return "already_existed";
					}
					else
					{
						return "first_try_true";
					}
				}
				else
				{
					if(heartTry > 0)
					{
						service.keycapLike(item);
						return "add_success";
					}
					else
					{
						return "first_try_false";
					}
					
				}
			}
			else
			{
				return "redirect:/login";
			}
			
		}
		
		//Model에 list를 담아두면 jsp페이지에 전달할 수 있다.
			@GetMapping("/list")
			String list(Pager pager, Model model, @RequestParam(required = false) String sort) {
				List<KeycapVo> list;
				
				//기본 은 신상품 순
			    if ("best".equals(sort)) {
			        list = service.listBest(pager);
			    } 
			    else if("desc".equals(sort)) {
			    	list = service.listPriceDesc(pager);
			    }
			    else if("asc".equals(sort)) {
			    	list = service.listPriceAsc(pager);
			    }
			    // 리뷰 많은 순
			    else if ("reviews".equals(sort)) {
					list = service.listReviewDesc(pager);
				}
			    else {
			        list = service.list(pager);
			    }
			    
			    // 각 상품에 대한 리뷰 수와 별점 평균을 저장할 맵
			    final Map<Integer, Integer> reviewTotals = new HashMap<>();
			    Map<Integer, Double> averageStars = new HashMap<>();
			    
			    for (KeycapVo keycap : list) {
			    	// pager 객체를 새로 생성하여 각 키캡에 대한 리뷰를 별도로 조회
    				Pager reviewPager = new Pager();
			    	List<ReviewVo> reviews = serviceReview.list(keycap.getKeycapNum(), reviewPager);
			        double totalStars = 0;
			        for (ReviewVo review : reviews) {
			            totalStars += review.getReviewStar();
			        }
			        //별점 평균
			        double averageStar = (reviews.size() > 0) ? totalStars / reviews.size() : 0;
			        
			        // 평균 별점을 소수점 첫째 자리까지만 표시하도록 반올림
			        averageStar = Math.round(averageStar * 10) / 10.0;
			        
			        reviewTotals.put(keycap.getKeycapNum(), reviews.size());
			        averageStars.put(keycap.getKeycapNum(), averageStar);
			    }
			    
				model.addAttribute("list", list);
				model.addAttribute("reviewTotals", reviewTotals); // 상품에 따른 리뷰 수 를 모델에 추가.
				model.addAttribute("averageStars", averageStars); // 상품에 따른 별점 평균을 모델에 추가.
				
				return path + "list";
			}
			
			//이미지 중복 처리(다른 컨트롤러 메서드 내에서 호출되어 사용되므로, 별도로 @GetMapping 또는 @PostMapping 어노테이션을 사용하여 HTTP 요청에 바로 매핑할 필요가 없음)
			public String handleUpload(MultipartFile file) throws IOException {
			    String filename = file.getOriginalFilename();
			    Path filePath = Paths.get(uploadPath2, filename);
			    
			    // URL 디코딩(저장되는 파일에 한국어가 있으면 인코딩된 #E@RE# 이런식으로 보이기 때문에 디코딩 한다.)
			    String decodedFilename = URLDecoder.decode(filename, StandardCharsets.UTF_8.toString());
			    
			    // 이미 파일이 존재할 경우 삭제
			    if (Files.exists(filePath)) {
			        Files.delete(filePath);
			    }

			    file.transferTo(filePath.toFile()); //파일 복사
			    
			    return "/keycapImages/" + decodedFilename; // 클라이언트에서 접근 가능한 이미지 URL
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
			@GetMapping("/add")
			String add() {
				return path + "add";
			}
			
			
			// upload 처리, 사용자가 보내온 form에 있는 값을 아무런 값이 안들어있는 new ReviewVo해서  만들어줌
			//그 객체 하나하나 를 set을 이용해서 넣어주면, MF가 작동하면서 try가 작동하면서 하나하나 값을 넣어줌
			//만약 리뷰번호(reviewNum)를 입력하지 않거나 잘못입력(String을 입력해야하는데 숫자(int)를 입력한 경우
			//스프링이 값을 넣지 못하므로 400에러 가 뜸
			//add.jsp에있는 name == uploadFile을 가져옴
			@PostMapping("/add")
			String add(KeycapVo item) {
				MultipartFile file = item.getUploadFile();
					try {
						if(file != null && !file.isEmpty()) {
							
							String filename = file.getOriginalFilename();
							
							file.transferTo(new File(uploadPath1 + filename) ); //파일 복사
						
							item.setKeycapImg(filename); //keycapImg에 파일네임 저장
						}
						
						service.add(item); //add를 호출하여 item 저장
						
					} catch (IllegalStateException e) {
						
						e.printStackTrace();
						
					} catch (IOException e) {
						
						e.printStackTrace();
					}
					
					return "redirect:list" + "?sort=null";		
					
				}

			@GetMapping("/{keycapNum}/update")
			String update(@PathVariable int keycapNum, Model model) {
				KeycapVo item = service.item(keycapNum);
				
				model.addAttribute("item", item);
				
				return path + "update";
			}
			
			@PostMapping("/{keycapNum}/update")
			String update(@PathVariable int keycapNum, KeycapVo item) {
				//첨부파일을 첨부했으면 표지를 바꾸고, 첨부하지 않았으면 안바꿈, 고로 기존에 표지가 있던없던 바꿀생각이 없음
				
				MultipartFile file = item.getUploadFile(); //MultipartFile을 item으로 읽어옴
					
					try {
						if(!file.isEmpty()) {
							String filename = file.getOriginalFilename();
							
							
						file.transferTo(new File(uploadPath1 + filename));
						
						if(item.getKeycapImg() != null) {
							File keycapImg = new File(uploadPath1 + item.getKeycapImg());
							keycapImg.delete();
						}
						
						item.setKeycapImg(filename);
						
					}
						
						item.setKeycapNum(keycapNum);
						
						service.update(item);
						
					} catch (IllegalStateException e) {
						e.printStackTrace();
					} catch (IOException e) {
						e.printStackTrace();
					}

					return "redirect:/keycap/list?sort=null";
				
			}
			
			@GetMapping("/{keycapNum}/delete")
			String delete(@PathVariable int keycapNum) {
				service.delete(keycapNum);
				
				return "redirect:/keycap/list?sort=null";
			}
			
			
}
