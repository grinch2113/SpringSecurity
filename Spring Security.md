# Spring Security

Spring Security是一个基于Spring的安全访问控制的解决方案的框架



## 过滤器

生活中的过滤器：净水器，门卫

web中的过滤器：当访问服务器的资源时，过滤器可以将请求拦截

作用：

 * 登录验证
 * 过滤敏感词汇

核心方法：doFilter

放行：chain.doFilter

放行后的代码在访问资源完毕后执行





## 配置Form认证

* UserDetails 存放用户信息的类
* UserDetailsService 查db获取UserDetails
* PasswordEncoder 密码加密匹配







## Spring Security过滤器

### FilterChainProxy

Spring Security只有一个真正的过滤器FilterChainProxy

![image-20220411000529807](C:\Users\HP\Desktop\assert\image-20220411000529807.png)



过滤器内部有过滤器链

![image-20220411000739576](C:\Users\HP\Desktop\assert\image-20220411000739576.png)



@EnableWebSecurity注解中，导入了一个配置类WebSecurityConfiguration，这个类的作用是通过WebSecurity生成FilterChainProxy对象



setFilterChainProxySecurityConfigurer方法创建了WebSecurity对象

1. 获取所有继承了WebSecurityConfigurerAdapter的配置类对象

2. 创建WebSecurity对象
3. 对所有配置类对象排序
4. 检查1中所有配置类对象是否有Order一样的
5. 将1中每个配置类对象添加到configurersAddedInInitializing中



springSecurityFilterChain方法创建了FilterChainProxy

1. 判断是否配置了WebSecurityConfigurerAdapter，没有则使用默认WebSecurityConfigurerAdapter配置
2. 添加过滤器链，并且设置最终的拦截过滤器
3. 调用WebSecurity的build方法
4. WebSecurity的build方法调用doBuild方法，该方法调用每个配置的init,configure等方法，最后调用WebSecurity的performBuild方法
5. performBuild方法先添加被忽略的请求的过滤器链，再遍历securityFilterChainBuilder，构建出所有过滤器链
6. 用4,5生成的过滤器链生成FilterChainProxy对象并返回





### SecurityFilterChain

那么，FilterChainProxy中的每个SecurityFilterChain是怎么生成的呢

我们已经发现，每个继承WebSecurityConfigurerAdapter的子类都会对应地创建一个SecurityFilterChain对象。重写的configure(HttpSecurity)方法就是用来配置SecurityFilterChain中的过滤器的

formlogin，authorizeRequests，logout方法会生成一个Configurer，在这个configurer的configure方法里会创建过滤器对象，并添加到HttpSecurity维护的Filter集合中







在创建SecurityFilterChain时还传入了一个RequestMatcher的对象，这是什么

* 判断请求url是否由当前SecurityFilterChain进行过滤



在antMatches之前配置anyRequest会报错，原因是什么？

1. antMatchers方法中，对于每个url参数，都会生成一个AntPathRequestMatcher对象

2. 调用HttpSecurity中的chainRequestMatchers方法，将1中的AntPathRequestMatcher对象添加到HttpSecurity维护的OrRequestMatcher对象中
3. HttpSecurity中的RequestMatcher是OrRequestMatcher，Or‘RequestMatcher里是RequestMatcher对象的集合
4. OrRequestMatcher的matcher方法按照RequestMatcher的添加顺序来调用每个RequestMatcher的matches方法
5. anyRequest方法生成一个AnyRequestMatcher对象，该对象的matches方法直接返回true

在antMatchers和antRequest方法中，会将新增的RequestMatcher追加到原有的RequestMatcher集合的尾部（调用集合的addAll方法）。因此，如果该RequestMatcher集合中前面存在AnyRequestMatcher，则在此后面的RequestMatcher都不起作用了。





## Form认证的实现

### SecurityContextHolder

用户认证后认证信息被存储在SecurityContextHolder中

![image-20220411124021512](C:\Users\HP\Desktop\assert\image-20220411124021512.png)

整个Spring Security只有一个SecurityContextHolder

SecurityContext：从SecurityContextHolder中获取，包含了认证信息

Authentication：一个接口，代表认证信息，里面有3个属性

1. Principal：用户信息，即UserDetails的一个实例
2. credentials：登录凭据，即密码。通常在认证成功后就会将UserDetails中的凭据删除以防泄露。
3. authorities：用户的角色或权限

实现：

* UsernamePasswordAuthenticationToken



### AuthenticationManager

是一个接口，表示认证过程的实现

默认实现：ProviderManager

![image-20220411131251322](C:\Users\HP\Desktop\assert\image-20220411131251322.png)

在一些场景下，会有多个ProdiverManager

* 有多条SecurityFilterChain，它们认证信息(Authentication)一样，但是认证过程不一样

![image-20220411132114381](C:\Users\HP\Desktop\assert\image-20220411132114381.png)







### AuthenticationProvider

一个接口，代表一种认证方式，多个AuthenticationProvider组成一个ProviderManager

实现：

* DaoAuthenticationProvider：基于用户名密码的认证

  

### DaoAuthenticationProvider

工作流程如下

![image-20220411135253091](C:\Users\HP\Desktop\assert\image-20220411135253091.png)

1. Spring Security的过滤器读取到用户名和密码，生成UsernamePasswordAuthenticationToken对象传给ProviderManager
2. ProviderManager使用DaoAuthenticationProvider来进行认证
3. DaoAuthenticationProvider从UserDetailsService中读取用户信息
4. DaoAuthenticationProvider用PasswordEncoder来匹配密码是否正确
5. DaoAuthenticationProvider返回UsernamePasswordAuthenticationToken，其中携带了principle属性，将认证信息写入SecurityContextHolder



### AuthenticationEntryPoint

用来发送一个要求用户凭证的HTTP响应，通常是重定向到登录界面

![image-20220411144018384](C:\Users\HP\Desktop\assert\image-20220411144018384.png)



1. 客户端发送一个未经认证的请求
2. FilterSecurityInterceptor抛出AccessDeniedException，表示请求没有经过认证
3. ExceptionTranslationFilter用AuthenticationEntryPoint重定向到登录页面，通常是LoginUrlAuthenticationEntryPoint
4. 浏览器请求登陆页面
5. 浏览器返回资源，该资源必须包含登录表单





### Form认证流程

![image-20220411143935130](C:\Users\HP\Desktop\assert\image-20220411143935130.png)

1. UsernamePasswordAuthenticationFilter读取到用户名和密码，生成UsernamePasswordAuthenticationToken对象传给AuthenticationManager
2. AuthenticationManager使用DaoAuthenticationProvider来进行认证
3. 如果认证失败

  * 清空SecurityContextHolder
  * 调用RememberMeServices的loginFail方法，如果没有配置remember me就不会执行这步操作
  * 调用AuthenticationFailureHandler

4. 如果认证成功

* SessionAuthenticationStrategy处理新的登录操作
* 将Authentication放进SecurityContextHolder
* 调用RememberMeService的loginSuccess方法
* ApplicationEventPublisher发布一个InteractiveAuthenticationSuccessEvent
* 调用AuthenticationSuccessHandler





# OAuth

OAuth 2.0 是一个授权协议，它允许软件应用代表（而不是充当）资源拥有者去访问资源拥有者的资源。应用向资源拥有者请求授权，然后取得令牌（token），并用它来访问资源，并且资源拥有者不用向应用提供用户名和密码等敏感数据。





## 角色划分

1. Resource Server： 被访问的资源
2. Authorization Server：OAuth授权中心
3. Resource Owner：用户
4. Client：调用Resource Server的客户端



## 应用场景

1. 第三方联合登录，如微信，qq登录
2. 调用第三方接口，如tapd访问gitlab





## 演示微信联合登录

微信公众号测试平台：

https://mp.weixin.qq.com/debug/cgi-bin/sandbox?t=sandbox/login&token=1820792496&lang=zh_CN 



准备工作：

1. 下载微信公众号测试工具

https://developers.weixin.qq.com/miniprogram/dev/devtools/download.html

2. 申请appid和密钥
3. 在公众号测试平台中，设置回调地址



登录流程：

1. 拼接授权地址，获取授权码code

```
https://open.weixin.qq.com/connect/oauth2/authorize?appid=ADDIP&redirect_uri=http://127.0.0.1:2000&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redire
```



2. 重定向到回调地址后，附带了一个code参数

```
http://127.0.0.1:2000/?code=001Ed20w3zhdrW2ldC0w3E5xdY0Ed20v&state=STATE 
```



3. 根据appid，密钥和授权码获取access_token和用户的OpenID

```
https://api.weixin.qq.com/sns/oauth2/access_token?appid=APPID&secret=SECRET&code=CODE&grant_type=authorization_code 
```

​	返回：

```
{"access_token":"45_vC59fGYQYgKmlcAGGvxejECMp3VMfkY7zKUEqZillG2R9p_DyXRpdAIIOdF8hCqebG3ZSuZeMmbIxeTcfOyW8w","expires_in":7200,"refresh_token":"45_yKtzn1Ti1TV-n-qbpwvnJ9o-xEY5wbRcPcSN-fwRoOvMXuiPOJcaYV6e1UKAoB4gEkxBqHRsWFIg2NEVccMzGQ","openid":"okYSmtzp4wWCrDCncMfGSRECVSeM","scope":"snsapi_userinfo"}
```



4. 根据access_token和OpenID拉去用户信息

```
https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID&lang=zh_CN
```





# JWT

JSON WEB Token 一般被用来在客户端和服务器间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证。



## 传统的token

传统的Token，例如：用户登录成功生成对应的令牌，以key为令牌，value为userid的方式 ，将该token存放到redis中，然后向客户端返回令牌。

客户端每次访问后端请求的时候，会传递该token在请求中，服务器端接收到该token之后，从redis中查询如果存在的情况下，则说明在有效期内，如果在Redis中不存在的情况下，则说明过期或者token错误。



## JWT的组成

1. header头部，用来存放加密算法的信息和token类型（一般为jwt）

```json
{"alg":"HS256","type":"JWT"}
```

2. payload载荷，用来存放信息，如用户信息，token过期时间等

```
{"userId":"1","username":"admin","expire_at","1649765408517"}
```

3. signature签名，用来验证jwt中的payload是否跟签发时候的内容一致





编码后的jwt长这样

```
eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2NiIsImlhdCI6MTY0OTcyOTY0NSwidXNlcm5hbWUiOiJhZG1pbiJ9.hHZnJDyYFLyP2MLOX46luBgQ5GRa5hEzdYTdYd635Ec
```



字符串有两个点号(.)将整个jwt分开成3部分，第一部分是header，第二部分是payload，第三部分是signature。其中header和payload是用base64进行编码的，signature是用加密算法对payload进行加密得到的。如果payload的内容被恶意篡改，jwt进行解码的时候会验签失败。





## JWT的优缺点

优点：

1.  无需访问redis，减轻了服务器的压力
2. 基于json，具有轻量级，跨语言的特性

缺点：

1. jwt一旦签发无法修改
2. 无法销毁jwt

原因：

* jwt存放在客户端

对策：

* 使jwt的有效期不要太长，以便更高频率地重新生成jwt 
