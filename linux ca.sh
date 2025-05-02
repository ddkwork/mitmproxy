#pamac install ca-certificates
#pamac remove ca-certificates

sudo cp /home/ddk/ca.crt /etc/ca-certificates/trust-source/anchors
sudo update-ca-trust

# wubantu not test
#将证书复制到/usr/local/share/ca-certificates目录（如果需要，请使用 mkdir）。文件名必须以 . 结尾.crt。
# sudo update-ca-trust

#termux not test
#/etc/tls/certs/