# JWT

### JWT 구조

* String lowSig = "header"+"payload"+"signature"
* base64(header)
* base64(payload)
* base64(HS256(lowSig))

![img.png](img.png)
![img_1.png](img_1.png)
