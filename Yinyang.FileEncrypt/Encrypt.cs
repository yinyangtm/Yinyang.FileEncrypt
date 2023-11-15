using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Yinyang.FileEncrypt
{
    public class Encrypt : EncryptBase
    {
        public Encrypt(int keySize, int blockSize, int bufferSize, int saltSize) : base(keySize, blockSize, bufferSize,
            saltSize)
        {
        }

        public void EncodeFile(string srcFilePath, string destFilePath, string password)
        {
            EncodeFile(srcFilePath, destFilePath, password, null, CancellationToken.None);
        }

        public async Task EncodeFileAsync(string srcFilePath, string destFilePath, string password,
            IProgress<int> progress, CancellationToken cancellationToken)
        {
            var salt = GetSalt();
            var key = GetKeyFromPassword(password, salt);
            var iv = GetIVFromPassword(password);

            using (var aes = new AesManaged())
            {
                var ct = CreateEncryptor(aes, key, iv);

                using (var outFileStream = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                {
                    await outFileStream.WriteAsync(salt, 0, SaltSize, cancellationToken);
                    await outFileStream.WriteAsync(aes.IV, 0, BlockSize / 8, cancellationToken);

                    using (var cryptoStream = new CryptoStream(outFileStream, ct, CryptoStreamMode.Write))
                    {
                        var info = GetFileInfo(srcFilePath, out var vs, out var len);

                        await cryptoStream.WriteAsync(BitConverter.GetBytes(len), 0, sizeof(int), cancellationToken);
                        await cryptoStream.WriteAsync(vs, 0, len, cancellationToken);

                        var filesize = info.Length;

                        using (var deflateStream = new DeflateStream(cryptoStream, CompressionMode.Compress))
                        {
                            using (var inFileStream = new FileStream(srcFilePath, FileMode.Open, FileAccess.Read))
                            {
                                long readsize = 0;
                                var buf = new byte[BufferSize];
                                while (true)
                                {
                                    await Task.Yield();

                                    var size = await inFileStream.ReadAsync(buf, 0, buf.Length, cancellationToken);

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

                                    await deflateStream.WriteAsync(buf, 0, size, cancellationToken);
                                }
                            }
                        }
                    }
                }
            }
        }

        private ICryptoTransform CreateEncryptor(AesManaged aes, byte[] key, byte[] iv)
        {
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.ISO10126;

            var ct = aes.CreateEncryptor(aes.Key, aes.IV);
            return ct;
        }

        private void EncodeFile(string srcFilePath, string destFilePath, string password, IProgress<int> progress,
            CancellationToken cancellationToken)
        {
            var salt = GetSalt();
            var key = GetKeyFromPassword(password, salt);
            var iv = GetIVFromPassword(password);

            using (var aes = new AesManaged())
            {
                var ct = CreateEncryptor(aes, key, iv);

                using (var outFileStream = new FileStream(destFilePath, FileMode.Create, FileAccess.Write))
                {
                    outFileStream.Write(salt, 0, SaltSize);
                    outFileStream.Write(aes.IV, 0, BlockSize / 8);

                    using (var cryptoStream = new CryptoStream(outFileStream, ct, CryptoStreamMode.Write))
                    {
                        var info = GetFileInfo(srcFilePath, out var vs, out var len);

                        cryptoStream.Write(BitConverter.GetBytes(len), 0, sizeof(int));
                        cryptoStream.Write(vs, 0, len);

                        var filesize = info.Length;

                        using (var deflateStream = new DeflateStream(cryptoStream, CompressionMode.Compress))
                        {
                            using (var inFileStream = new FileStream(srcFilePath, FileMode.Open, FileAccess.Read))
                            {
                                long readsize = 0;
                                var buf = new byte[BufferSize];
                                while (true)
                                {
                                    var size = inFileStream.Read(buf, 0, buf.Length);

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

                                    deflateStream.Write(buf, 0, size);
                                }
                            }
                        }
                    }
                }
            }
        }

        private static FileInfo GetFileInfo(string srcFilePath, out byte[] vs, out int len)
        {
            var fh = new FileHeader();
            var info = new FileInfo(srcFilePath);
            fh.CreationTime = info.CreationTime.Ticks;
            fh.LastAccessTime = info.LastAccessTime.Ticks;
            fh.LastWriteTime = info.LastWriteTime.Ticks;
            fh.Name = info.Name;
            vs = fh.SerializeToByteArray();
            len = vs.Length;
            return info;
        }
    }
}
