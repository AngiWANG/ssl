# ssl
默认从javax.net.ssl.keyStore加载密钥库，从javax.net.ssl.trustStore加载信任库
例如：
```
-Djavax.net.ssl.keyStore=D:\Workspace\STS\ssl\src\main\resources\serverKeys -Djavax.net.ssl.keyStorePassword=password -Djavax.net.ssl.trustStore=D:\Workspace\STS\ssl\src\main\resources\serverTrust -Djavax.net.ssl.trustStorePassword=password
```