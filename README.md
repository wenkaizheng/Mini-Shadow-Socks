# self-learning

This project is a simple version of socks5 proxy software in Golang.  

Our approach is to create two proxies for network transfer (Server and Local).  
Usually, when users visit websites, their computers will performance DNS lookup for server IP, 
and then do the TCP handshake for establishing a TCP connection.
Finally, they will send requests(https or http).  

This whole process can be done by user applications and servers, so basically we have 2 nodes.   
User -> Server   
User <- Server   
In our implementation, we add two more nodes, which are Local Proxy and Server Proxy sitting in-between users and real servers.    
User -> Local Proxy -> Server Proxy -> Server   
User <- Local Proxy <- Server Proxy <- Server   
The reason is that we need to encrypt all traffic data in order to bypass firewall.   
When a user initiates local proxy, it will send username and password, and then server proxy will compare them with pairs of username and corresponding password stored in data.csv.  
For matters of security, we only store sha512 values of salted usernames and salted passwords.
After authentication steps, local proxy will send encode and decode table (256-byte array) to server proxy for future encryption usage.   
When handling requests from user applications and responds from read servers, we use multiple go-routines so that we handel each request simultaneously.  
We also have heartbeat message mechanism to detect user is online or offline, and we will close session if user is offline.

For users part, they need to set up their chrome with socks5 protocol.   
Socks5 : https://tools.ietf.org/html/rfc1928  
How to set up chrome and run each proxy :   
- install the Chrome extension SwitchyOmega  
- open options  
- added proxy:
  - Protocol: SOCKS5 
  - Server: 127.0.0.1
  - Port: 5209 (as local_port defined in config.json)  
- make sure you are using proxy rather than direct connection
- go to project folder and make
- run server prxoy ./mySSServer
- run local proxy ./mySSLocal
- if you want to try run the server proxy in server (other IP rather than 127.0.0.1),email us
  wenkaizheng@email.arizona.edu
  jiachengyang@email.arizona.edu
  we will open port and server for you
- we also support different version executable file (make windows, mac or linux). Which means user can use local proxy without Go compiler.
- do not forget to run local proxy before run server proxy

Browsers will send specific network packets to local proxy, and then local proxy transfers them to sever proxy.
 Server Proxy will respond them according to packets it receives. 
 After the sock5 protocol process is done, both proxies will continue to transfer the normal data packet.   
The curretn goal is to create a UDP version and front-end html  
Also make a record for the websites which are visited by users
