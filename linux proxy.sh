#system mode not passed
# /etc/environment
http_proxy=http://127.0.0.1:6666
https_proxy=http://127.0.0.1:6666
ftp_proxy=http://127.0.0.1:6666
no_proxy="127.0.0.1,localhost"


#user mode passed
#/etc/profile
export http_proxy=http://127.0.0.1:6666
export https_proxy=http://127.0.0.1:6666
export ftp_proxy=http://127.0.0.1:6666
export no_proxy="127.0.0.1,localhost"

