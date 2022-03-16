
# In Vivo Fuzzing


## In-vivo Fuzzing 架構

![](https://i.imgur.com/GveELv9.png)


![](https://i.imgur.com/yXMugHQ.png)


## 套用成功的網路程式 CVE 

使用 **一般連線資料** 跟接近 CVE exploit code 的 payload 讓程式蒐集 seed


| Program | time to exploit | CVE | ASAN enable | 
| -------- | -------- | -------- |-------- |
| MySQL-5.6.25     | 8 min 43s    | CVE-2017-3599     | |
| Httpd-2.4.25     | 2 min 21s     | CVE-2017-7659    | |
| Nginx-1.4.0     | 3 min 02s     | CVE-2013-2028     | |
| Redis-5.0-rc1     | 2 min 09s     | CVE-2013-2028   | |
| Exim- 4.92.1     | 1 day 3 hr 56s     | CVE-2019-16928   | yes |
| Live555-0.92      | 21 min 16s     | CVE-2018-4013    | |
| Pure-FTPd 1.0.49     | 650ms     | CVE-2018-4013    | |
| ntp-4.2.8p8     | 5 hr 57 min 43 s     | CVE-2016-7434    | |
| tinydtls-0.8.2     | 15 min 19 s   | CVE-2017-7243     | |


## Docker container 主要內容
```
~/
 - BSA_test (in-vivo Runtime library)
 - eval (Program CVE)
     - Nginx
         - entry.conf (適合的 fuzzing entry point function name)
         - tf_build.sh (設定 CC 跟 entry.conf，並自動 configure 跟 make)
         - bof.py (CVE POC)
     - MySQL
     - ...
```


## 測試流程概要
先 cd /BSA_test

1. 編譯 in-vivo fuzzing 框架
    * `/BSA_rt` make
    * `/third_party/afl-2.52b/BSA_mode/` make

2. 編譯待測程式
    * `CC` 須為 `~/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast` 的絕對位置
    * `CFLAGS="-mllvm -config=/root/nginx-1.4.0/entry.conf -mllvm -level=2 -pthread"`
    * 每個 cve 資料夾下都有個 tf_build.sh ，直接跑 ./tf_build.sh 即可
3. 啟動 IA_server：`python3 IA_server.py`（in `/BSA_serv`）
4. 啟動待測程式
5. 送出正常 request，確認待測程式進入正常流程
6. 送出 fuzzing request：`./req 1 <待測程式pid> <待測程式tid> 0`
7. 送出正常 request，開始 fuzzing


## 以 Nginx 為例


```
cd ~/BSA_test
cd BSA_rt
make
cd ~/BSA_test/third_party/afl-2.52b/BSA_mode/
make
cd ~/nginx-1.4.0
./tf_build.sh
./objs/nginx -p .  # start running the program


# open another pannel or use tmux to sperate pannel
cd ~/BSA_test/BSA_serv
python3 IA_server.py # launch the IA server



# open antoher pannel
# check whetehr the target program run successfully
curl localhost 
python bof.py
# send fuzzing request
~/req 1 [pid of the program] [thread id of the program] 0
# send normal workload to target program
python bof.py
```

## 以 Exim 為例


### 編譯 + 啟動 exim daemon
```
cd ~/eval/exim

echo "smtp_setup_msg" > entry.conf

CC="/root/BSA_test/third_party/afl-2.52b/afl-BSA-clang-fast"
CFLAGS=-mllvm -level=2 -mllvm -config=/root/eval/exim/src/entry.conf
AFL_USE_ASAN=1 make


./build-Linux-x86_64/exim -bd -d
```

![](https://i.imgur.com/ZfzxRWi.png)


### 啟動 In-vivo Fuzzing server
```
cd ~/BSA_test/BSA_serv && python3 IA_server.py
```

### 執行一般連線 + 惡意連線
```
python normal.py
python half_attack.py

```


### 發送 fuzzing request
```
~/req 1 [process id] [thread id] 0
```

### 成功用 invivo + AFL 找到 bug
![](https://i.imgur.com/x2KV2eW.png)