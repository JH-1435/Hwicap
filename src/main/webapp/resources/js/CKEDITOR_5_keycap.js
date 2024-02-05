//CKEDITOR 5에서 알려주는 자체어댑터(개인용) 설정
class MyUploadAdapter {
    constructor(loader, jwtToken, csrfToken) {
        this.loader = loader;
        this.jwtToken = jwtToken;
        this.csrfToken = csrfToken;
    }

    upload() {
        return this.loader.file
            .then(file => new Promise((resolve, reject) => {
                const data = new FormData();
                data.append('upload', file);

                const xhr = new XMLHttpRequest();
                xhr.open('POST', '/keycap/uploadImage', true);
                xhr.setRequestHeader('X-CSRF-TOKEN', this.csrfToken);
                xhr.setRequestHeader('Authorization', 'Bearer ' + this.jwtToken);

                xhr.upload.onprogress = evt => {
                    if (evt.lengthComputable) {
                        this.loader.uploadTotal = evt.total;
                        this.loader.uploaded = evt.loaded;
                    }
                };

                xhr.onreadystatechange = () => {
                    if (xhr.readyState === 4) {
                        if (xhr.status !== 200) {
                            reject('Upload failed');
                            return;
                        }

                        const response = JSON.parse(xhr.responseText);

                        resolve({
                            default: response.url
                        });
                    }
                };

                if (xhr.send) {
                    xhr.send(data);
                }
            }));
    }

    abort() {
        // Upload abort logic goes here.
    }
}

//쿠키에 저장된 jwt 토큰 찾기
function getCookie(name) {
    var cookieArr = document.cookie.split(";");
    
    for(var i = 0; i < cookieArr.length; i++) {
        var cookiePair = cookieArr[i].split("=");
        
        if(name == cookiePair[0].trim()) {
            return decodeURIComponent(cookiePair[1]);
        }
    }
    
    // 못찾으면 null 반환
    return null;
}

//CKEDITOR 5, dom이 완전히 로딩 된 후에 ck에디터 실행.
document.addEventListener("DOMContentLoaded", function() {
    var jwtToken = getCookie('token'); // 'token'은 실제 JWT 토큰이 저장된 쿠키의 명칭
    var csrfToken = '<%= request.getSession().getAttribute("CSRF-TOKEN") %>';
    
    ClassicEditor
        .create(document.querySelector('#keycapContent'), {
        	simpleUpload: {
                uploadUrl: 'D:/HwicapUpload/keycapImgF/',
                withCredentials: true,
                headers: {
                    'X-CSRF-TOKEN': csrfToken,
                    Authorization: 'Bearer ' + jwtToken
                }
            }
        //MyUploadAdapter 클래스를 통해 이미지를 업로드하고, 업로드된 이미지의 URL을 반환받아 CKEditor에서 사용
        }).then(editor => {
            editor.plugins.get('FileRepository').createUploadAdapter = (loader) => {
                return new MyUploadAdapter(loader, jwtToken, csrfToken);
            };
            
            // 특정 CKEditor 인스턴스가 생성된 후에 CSS 스타일 요소를 동적으로 생성
            let style1 = document.createElement('style');
            style1.innerHTML = `
            .ck-content .image img {
                display: block;
                height: auto;
                margin: 0 auto;
                width: 1020px;
                height: 100%;
            }`;
            
            let style2 = document.createElement('style');
            style2.innerHTML = `
            	.ck-content .image-inline img, .ck-content .image-inline picture {
			    flex-grow: 1;
			    flex-shrink: 1;
			}`;
            
            // 생성된 것을 CKEditor의 iframe에 추가하는 방식으로 작동
            editor.ui.view.editable.element.parentElement.appendChild(style1);
            editor.ui.view.editable.element.parentElement.appendChild(style2);
        });
});