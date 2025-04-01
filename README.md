# CCS2022-InviCloak

The code of InviCloak. Please refer to our [paper (CCS'22 )](https://dl.acm.org/doi/10.1145/3548606.3559336) for detail.

Please check this [repo](https://github.com/SHiftLin/chromium) for the code of the Chromium patch mentioned in the paper.

## Prerequisites
- ```sudo apt install libpcre3 libpcre3-dev```
- Apply for a TLS certificate of your domain and replace `server.pem` and `server.key` in `cert/`.

## Getting started
```
make dep
make all
```

Run `sudo ./run_nginx.sh` to start an NGINX server.  
Visit the index page of the server to play with the example login function with traffic encrypted by InviCloak.  
*Optional:* Install the extension in `extension/` to enable the integrity verifier.

## Directories and files
- `cert`: Certificate examples. Should apply for your own certificates for production.  
- `extension`: Browser extension, i.e. the integrity verifier described in our paper.  
- `mod`: NGINX module, i.e. the server proxy described in our paper.  
- `static`: Test webpages.  
  - `static/swjs`: JavaScript library, i.e. the client proxy described in the paper. 
- `nginx.conf`: An NGINX configuration example for the server proxy. Check Appendix B in our [extended paper](https://arxiv.org/abs/2209.01541) for explanation.

## Bibtex
```
@inproceedings{CCS22-InviCloak,
    author = {Lin, Shihan and Xin, Rui and Goel, Aayush and Yang, Xiaowei},
    title = {InviCloak: An End-to-End Approach to Privacy and Performance in Web Content Distribution},
    year = {2022},
    publisher = {ACM},
    booktitle = {Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security},
    pages = {1947–-1961},
    location = {Los Angeles, CA, USA}
}
```
