# pokeyproxy
A basic TCP proxy
```
usage: pokeyproxy.py [-h] [--local-port LOCAL_PORT]
                     [--remote-port REMOTE_PORT] [--remote-host REMOTE_HOST]
                     [--receive-first] [--nocolor] [--verbose]
                     [--timeout TIMEOUT]

optional arguments:
  -h, --help            show this help message and exit
  --local-port LOCAL_PORT
                        Specify bind port (default = 8520)
  --remote-port REMOTE_PORT
                        Specify the remote port
  --remote-host REMOTE_HOST
                        Specify the remote host
  --receive-first       Connect and receive before sending data
  --nocolor             Skip colors in output
  --verbose             Enable verbose output
  --timeout TIMEOUT     Request timeout in s (Default=3s)
```
