using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Yinyang.FileEncrypt
{
    public class EncryptBase
    {
        protected int BlockSize;
        protected int BufferSize;
        protected int KeySize;
        protected int SaltSize;

        public int IterationCount { get; set; } = 1024;

        public string GetExtension { get; } = ".yfe";

        public EncryptBase(int keySize, int blockSize, int bufferSize, int saltSize)
        {
            KeySize = keySize;
            BlockSize = blockSize;
            BufferSize = bufferSize * 32;
            SaltSize = saltSize;
        }

        public byte[] GetIVFromPassword(string password)
        {
            var deriveBytes = new Rfc2898DeriveBytes(password + DateTime.Now.Ticks, SaltSize, IterationCount, HashAlgorithmName.SHA1);
            return deriveBytes.GetBytes(BlockSize / 8);
        }

        public byte[] GetKeyFromPassword(string password, byte[] salt)
        {
            var deriveBytes = new Rfc2898DeriveBytes(password, salt, IterationCount, HashAlgorithmName.SHA1);
            return deriveBytes.GetBytes(KeySize / 8);
        }

        public byte[] GetSalt()
        {
            var deriveBytes = new Rfc2898DeriveBytes(DateTime.Now.Ticks.ToString(), SaltSize, IterationCount, HashAlgorithmName.SHA1);
            return deriveBytes.Salt;
        }

        public byte[] ReadBytesFromStream(Stream stream, int offset, int count)
        {
            using (var mem = new MemoryStream())
            {
                var totalSize = 0;
                var buf = new byte[count];
                while (true)
                {
                    var size = stream.Read(buf, offset, count - totalSize);
                    if (size == 0)
                    {
                        break;
                    }

                    mem.Write(buf, 0, size);
                    totalSize += size;
                }

                return mem.ToArray();
            }
        }

        public async Task<byte[]> ReadBytesFromStreamAsync(Stream stream, int offset, int count,
            CancellationToken cancellationToken)
        {
            using (var mem = new MemoryStream())
            {
                var totalSize = 0;
                var buf = new byte[count];
                while (totalSize < count)
                {
                    var size = await stream.ReadAsync(buf, offset, Math.Min(count - totalSize, buf.Length),
                        cancellationToken);
                    if (size == 0)
                    {
                        break;
                    }

                    await mem.WriteAsync(buf, 0, size, cancellationToken);
                    totalSize += size;
                }

                return mem.ToArray();
            }
        }
    }
}
