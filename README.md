# wportscan
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

wportscan is port scan program. Made for extreme long scans (months).

## Features
- Made in c99 language.
- Low SLOC and memory usage.
- Automatic export session.
- Range based scan for IP.
- Doesn't use multiple threads. (pretty standard for today)

## Installation

```sh
git clone --depth 1 https://github.com/7244/wportscan && \
cd wportscan && \
mkdir include && \
cd include && \
git clone --depth 1 https://github.com/7244/WITCH && \
cd .. && \
make
```

### Usage
1. scanning 192.168.1.1/24 for telnet port with speed of 100 ip per second
    ```
    $ wportscan --ip 192.168.1.1/24 --port 23 --syndelay .01
    $ ls
    export_16a10c5b5a74.wps  output_16a10c5b5a74.wps
    $ wportscan --readoutput output_16a10c5b5a74.wps
    readoutput for file output_16a10c5b5a74.wps
    total output: 1
    192.168.1.1:23
    ```

### Depends On
* https://github.com/7244/WITCH


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
