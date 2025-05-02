package mitmproxy

//Clash的mitm功能可以通过在配置文件中设置来实现。以下是一个示例配置文件，其中包含了mitm功能的设置：
//
//
//# HTTP和HTTPS代理
//proxies:
//  - name: "http-proxy"
//    type: http
//    server: 127.0.0.1
//    port: 7890
//
//  - name: "https-proxy"
//    type: http
//    server: 127.0.0.1
//    port: 7890
//    tls: true
//    skip-cert-verify: true
//
//# mitm设置
//mitm:
//  enabled: true
//  certificate: /path/to/certificate.pem
//  key: /path/to/private.key
//  skip-domain:
//    - "*.google.com"
//
//
//在上面的配置文件中，我们设置了两个代理，一个是HTTP代理，另一个是HTTPS代理，并且开启了mitm功能。我们还设置了证书和私钥的路径，并且指定了需要跳过mitm的域名。
//
//要设置证书和私钥，您需要先生成自己的证书和私钥。您可以使用openssl工具来生成它们。以下是一些示例命令：
//
//生成证书：
//
//
//openssl req -x509 -newkey rsa:4096 -keyout private.key -out certificate.pem -days 365 -nodes
//
//
//生成私钥：
//
//
//openssl genrsa -out private.key 4096
//
//
//生成证书请求：
//
//
//openssl req -new -key private.key -out certificate.csr
//
//
//请注意，这些命令将生成自签名证书，因此您需要在使用mitm功能之前将其导入到您的操作系统中的受信任根证书颁发机构中。
//
//一旦您设置了证书和私钥的路径，并将配置文件保存为yaml格式，您可以在启动Clash时指定该文件的路径。例如：
//
//
//clash -d /path/to/config/dir
//
//
//这将启动Clash并加载配置文件。现在您可以使用您的HTTP和HTTPS代理，并且Clash将自动为您生成证书并拦截所有HTTPS流量进行mitm攻击。
