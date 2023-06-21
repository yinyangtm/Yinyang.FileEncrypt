using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Yinyang.FileEncrypt
{
    public class Decrypt : EncryptBase
    {
        public Decrypt(int keySize, int blockSize, int bufferSize, int saltSize) : base(keySize, blockSize, bufferSize,
            saltSize)
        {
        }

        public void DecodeFile(string srcFilePath, string destFolderPath, string password)
        {
            DecodeFile(srcFilePath, destFolderPath, password, null, CancellationToken.None);
        }


        public void DecodeFile(string srcFilePath, string destFolderPath, string password, IProgress<int> progress,
            CancellationToken cancellationToken)
        {
            using (var aes = new AesManaged())
            {
                SetAes(aes);

                using (var inFileStream = new FileStream(srcFilePath, FileMode.Open, FileAccess.Read))
                {
                    var salt = ReadBytesFromStream(inFileStream, 0, SaltSize);
                    var key = GetKeyFromPassword(password, salt);
                    aes.Key = key;

                    var iv = new byte[BlockSize / 8];
                    iv = ReadBytesFromStream(inFileStream, 0, iv.Length);
                    aes.IV = iv;

                    var ct = aes.CreateDecryptor(aes.Key, aes.IV);

                    var srcinfo = new FileInfo(srcFilePath);
                    var filesize = srcinfo.Length;


                    using (var cryptoStream = new CryptoStream(inFileStream, ct, CryptoStreamMode.Read))
                    {
                        FileHeader fh = null;

                        try
                        {
                            var bs = ReadBytesFromStream(cryptoStream, 0, sizeof(int));
                            var len = BitConverter.ToInt32(bs, 0);
                            var vs = ReadBytesFromStream(cryptoStream, 0, len);
                            fh = FileHeader.ByteArrayToObject(vs);
                        }
                        catch (Exception err)
                        {
                            throw new NotValidPasswordException(err.Message);
                        }

                        var name = fh.Name;

                        if (!Directory.Exists(destFolderPath))
                        {
                            Directory.CreateDirectory(destFolderPath);
                        }

                        var destFilePath = Path.Combine(destFolderPath, name);

                        using (var ds = new DeflateStream(cryptoStream, CompressionMode.Decompress))
                        {
                            using (var outFs = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                            {
                                long readsize = 0;
                                var buf = new byte[BufferSize];
                                while (true)
                                {
                                    var size = ds.Read(buf, 0, buf.Length);

                                    readsize += size;

                                    if (size == 0)
                                    {
                                        break;
                                    }

                                    progress?.Report((int)Math.Round((double)(100 * readsize) / filesize));

                                    if (cancellationToken.IsCancellationRequested)
                                    {
                                        cancellationToken.ThrowIfCancellationRequested();
                                    }

                                    outFs.Write(buf, 0, size);
                                }
                            }
                        }

                        var info = new FileInfo(destFilePath);
                        info.CreationTime = new DateTime(fh.CreationTime);
                        info.LastAccessTime = new DateTime(fh.LastAccessTime);
                        info.LastWriteTime = new DateTime(fh.LastWriteTime);
                    }
                }
            }
        }

        public async Task DecodeFileAsync(string srcFilePath, string destFolderPath, string password,
            IProgress<int> progress,
            CancellationToken cancellationToken)
        {
            using (var aes = new AesManaged())
            {
                SetAes(aes);

                using (var inFileStream = new FileStream(srcFilePath, FileMode.Open, FileAccess.Read))
                {
                    var salt = await ReadBytesFromStreamAsync(inFileStream, 0, SaltSize, cancellationToken);
                    var key = GetKeyFromPassword(password, salt);
                    aes.Key = key;

                    var iv = new byte[BlockSize / 8];
                    iv = await ReadBytesFromStreamAsync(inFileStream, 0, iv.Length, cancellationToken);

                    aes.IV = iv;

                    var ct = aes.CreateDecryptor(aes.Key, aes.IV);

                    var srcinfo = new FileInfo(srcFilePath);
                    var filesize = srcinfo.Length;

                    using (var cryptoStream = new CryptoStream(inFileStream, ct, CryptoStreamMode.Read))
                    {
                        FileHeader fh;

                        try
                        {
                            var bs = ReadBytesFromStream(cryptoStream, 0, sizeof(int));
                            var len = BitConverter.ToInt32(bs, 0);
                            var vs = ReadBytesFromStream(cryptoStream, 0, len);
                            fh = FileHeader.ByteArrayToObject(vs);
                        }
                        catch (Exception err)
                        {
                            throw new NotValidPasswordException(err.Message);
                        }

                        var name = fh.Name;

                        if (!Directory.Exists(destFolderPath))
                        {
                            Directory.CreateDirectory(destFolderPath);
                        }

                        var destFilePath = Path.Combine(destFolderPath, name);

                        using (var ds = new DeflateStream(cryptoStream, CompressionMode.Decompress))
                        {
                            using (var outFs = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                            {
                                long readsize = 0;
                                var buf = new byte[BufferSize];
                                while (true)
                                {
                                    await Task.Yield();

                                    var size = await ds.ReadAsync(buf, 0, buf.Length, cancellationToken);

                                    readsize += size;

                                    if (size == 0)
                                    {
                                        break;
                                    }

                                    progress?.Report((int)Math.Round((double)(100 * readsize) / filesize));

                                    if (cancellationToken.IsCancellationRequested)
                                    {
                                        cancellationToken.ThrowIfCancellationRequested();
                                    }

                                    await outFs.WriteAsync(buf, 0, size, cancellationToken);
                                }
                            }
                        }

                        var info = new FileInfo(destFilePath);
                        info.CreationTime = new DateTime(fh.CreationTime);
                        info.LastAccessTime = new DateTime(fh.LastAccessTime);
                        info.LastWriteTime = new DateTime(fh.LastWriteTime);
                    }
                }
            }
        }

        public FileHeader GetFileHeader(string srcFilePath, string password)
        {
            using (var aes = new AesManaged())
            {
                SetAes(aes);

                using (var inFileStream = new FileStream(srcFilePath, FileMode.Open, FileAccess.Read))
                {
                    var salt = ReadBytesFromStream(inFileStream, 0, SaltSize);
                    var key = GetKeyFromPassword(password, salt);
                    aes.Key = key;

                    var iv = new byte[BlockSize / 8];
                    iv = ReadBytesFromStream(inFileStream, 0, iv.Length);
                    aes.IV = iv;

                    var ct = aes.CreateDecryptor(aes.Key, aes.IV);

                    using (var cryptoStream = new CryptoStream(inFileStream, ct, CryptoStreamMode.Read))
                    {
                        try
                        {
                            var bs = ReadBytesFromStream(cryptoStream, 0, sizeof(int));
                            var len = BitConverter.ToInt32(bs, 0);
                            var vs = ReadBytesFromStream(cryptoStream, 0, len);
                            return FileHeader.ByteArrayToObject(vs);
                        }
                        catch (Exception err)
                        {
                            throw new NotValidPasswordException(err.Message);
                        }
                    }
                }
            }
        }

        private void SetAes(AesManaged aes)
        {
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.ISO10126;
        }
    }
}
