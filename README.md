<meta property="og:image" content="https://opengraph.githubassets.com/1/dansiup44/ezscan" />

# ezscan - 📡A eazy, lightweight, multi-threaded Python port scanner.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![No dependencies](https://img.shields.io/badge/dependencies-none-orange)

> **WITHOUT the need to install external libraries!**

---

# Using:
Launch: 

python ezscan.py -i [input] -o [output] -t [threads] -p [ports] -n [timeout] -l [look]

-i [input file (Ranges, CIDR, IP)] 

-o [output file (If it does not exist, will be created)] 

-t [threads (default=128)] 

-p [ports (1,2,3,4-10)] 

-n [timeout ms (default=3000)] 

-l [look (1=IP 2=IP:Ports)]

---

## Installation:
```bash
git clone https://github.com/dansiup44/ezscan.git
cd ezscan
```

# Credits:
Tool was created by dansiup44 (MIT license)
