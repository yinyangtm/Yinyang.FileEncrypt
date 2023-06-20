# Yinyang.FileEncrypt

This is a C# library for simply encrypting and decrypting files.
The encrypted files are compressed, yet retain the original file information.

シンプルにファイルを暗号化・複合化するC#ライブラリです。
暗号化ファイルは圧縮され、元のファイル情報を保持します。

---

## Getting started

Install Yinyang.FileEncrypt nuget package.

NuGet パッケージ マネージャーからインストールしてください。

- [Yinyang.FileEncrypt](https://www.nuget.org/packages/Yinyang.FileEncrypt)

> ```powershell
> Install-Package Yinyang.FileEncrypt
> ```

---

## Basic Usage

```c#
private const int KeySize = 256;
private const int BlockSize = 128;
private const int BufferSize = 4096;
private const int SaltSize = 128;

// Init Encrypt
var encrypt = new Encrypt(KeySize, BlockSize, BufferSize, SaltSize);

// File Encrypt
encrypt.EncodeFile(file_path, encrypt_file_name, password);

// Init Decrypt
var decrypt = new Decrypt(KeySize, BlockSize, BufferSize, SaltSize);

// File Decrypt
decrypt.DecodeFile(encrypt_file_path, dest_folder_path, password);


```

