package kr.ac.jh.keycap.util;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@EnableWebMvc
public class WebConfig extends WebMvcConfigurerAdapter {
	//이 설정을 통해 '/images/'로 시작하는 URL 요청은 'file:///D:/HwicapUpload/userImgF/' 디렉토리로 매핑 즉 공유 폴더가 됨.
	// 근데 제 3자가 이 폴더가 없어도 공유 폴더이기에 그대로 사진이 보임. 보안적인 문제(제 3자가 나의 폴더를 보는 등)를 해결함.
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        	registry.addResourceHandler("/images/**")
        			.addResourceLocations("file:///D:/HwicapUpload/userImgF/");
        	registry.addResourceHandler("/keycapImages/**")
			.addResourceLocations("file:///D:/HwicapUpload/keycapImgF/");
    }
}
