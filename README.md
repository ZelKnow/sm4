# SM4加密算法

国密SM4算法的python实现，SM4算法描述见[标准文件](https://github.com/guanzhi/GM-Standards/blob/master/GMT%E6%AD%A3%E5%BC%8F%E6%A0%87%E5%87%86/GMT%200002-2012%20SM4%E5%88%86%E7%BB%84%E5%AF%86%E7%A0%81%E7%AE%97%E6%B3%95.pdf)。

## 依赖

```
poetry install
```
或
```
pip install requirements.txt
```

## 使用
```
usage: sm4.py [-h] [--iv IV] [--source_type {input,bin_file,image}] [--output OUTPUT]
              {encrypt,decrypt} {ecb,cbc} source key

SM4加解密

positional arguments:
  {encrypt,decrypt}     加密或解密
  {ecb,cbc}             加密模式
  source                加密/解密目标
  key                   密钥

optional arguments:
  -h, --help            show this help message and exit
  --iv IV               初始化向量
  --source_type {input,bin_file,image}
                        加密目标类型
  --output OUTPUT       输出文件名
```

### 示例

- 普通加解密
  ```
  python3 sm4.py encrypt ecb eifjweqorifjerioqfjioerwjferwjiofjoerwif abcdefghijklmnop
  # 4cb15b0121253054c250a960eb23d27cc142417c983cd76bc25102cdf663503bf38f332182bdbb09b9ec903703453cf5
  python3 sm4.py decrypt ecb 4cb15b0121253054c250a960eb23d27cc142417c983cd76bc25102cdf663503bf38f332182bdbb09b9ec903703453cf5 abcdefghijklmnop
  # eifjweqorifjerioqfjioerwjferwjiofjoerwif
  ```
- 使用ECB模式对二进制文件logo.png进行加解密
  ```
  python3 sm4.py encrypt ecb logo.png abcdefghijklmnop --source_type=bin_file --output out
  python3 sm4.py decrypt ecb out abcdefghijklmnop --source_type=bin_file --output out.png
  ```
- 使用CBC模式对图片进行加密
  ```
  python3 sm4.py encrypt cbc logo.png aghilasdfgsdsdfg --source_type image --output test.png --iv abcdefghi
  ```