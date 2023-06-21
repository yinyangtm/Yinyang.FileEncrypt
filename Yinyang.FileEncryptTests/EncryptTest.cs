using Yinyang.FileEncrypt;

namespace Yinyang.FileEncryptTests;

[TestClass]
public class EncryptTest
{
    private const string Password = "myA89ezawUTZG#yu&a$3Cd2HUfeg!g93";
    private const int BytesToRead = sizeof(long);

    private const int KeySize = 256;
    private const int BlockSize = 128;
    private const int BufferSize = 4096;
    private const int SaltSize = 128;

    [TestMethod]
    public async Task NotValidPasswordAsyncTest()
    {
        var encrypt = new Encrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var test_file_name = "testfile.dat";
        var encrypt_file_name = test_file_name + encrypt.GetExtension;

        encrypt.EncodeFile(test_file_name, encrypt_file_name, Password);

        var decrypt = new Decrypt(KeySize, BlockSize, BufferSize, SaltSize);

        Task Dfa() => decrypt.DecodeFileAsync(encrypt_file_name, Path.Combine(Directory.GetCurrentDirectory(), "./dec"), Password + "NotValid", null, CancellationToken.None);
        await Assert.ThrowsExceptionAsync<NotValidPasswordException>(Dfa);
    }

    [TestMethod]
    public void NotValidPasswordTest()
    {
        var encrypt = new Encrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var test_file_name = "testfile.dat";
        var encrypt_file_name = test_file_name + encrypt.GetExtension;

        encrypt.EncodeFile(test_file_name, encrypt_file_name, Password);

        var decrypt = new Decrypt(KeySize, BlockSize, BufferSize, SaltSize);

        Action fha = () => decrypt.GetFileHeader(encrypt_file_name, Password + "NotValid");

        Assert.ThrowsException<NotValidPasswordException>(fha);

        var dfa = () => decrypt.DecodeFile(encrypt_file_name, Path.Combine(Directory.GetCurrentDirectory(), "./dec"),
            Password + "NotValid");

        Assert.ThrowsException<NotValidPasswordException>(dfa);
    }


    [TestMethod]
    public void TestFileTest()
    {
        var encrypt = new Encrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var test_file_name = "testfile.dat";
        var encrypt_file_name = test_file_name + encrypt.GetExtension;

        encrypt.EncodeFile(test_file_name, encrypt_file_name, Password);

        var original = new FileInfo(test_file_name);

        var decrypt = new Decrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var fh = decrypt.GetFileHeader(encrypt_file_name, Password);

        Assert.AreEqual(test_file_name, fh.Name);
        Assert.AreEqual(original.CreationTime, new DateTime(fh.CreationTime));
        Assert.AreEqual(original.LastWriteTime, new DateTime(fh.LastWriteTime));

        decrypt.DecodeFile(encrypt_file_name, Path.Combine(Directory.GetCurrentDirectory(), "./dec"), Password);


        var decrypt_file = new FileInfo("./dec/" + test_file_name);

        Assert.AreEqual(true, FilesAreEqual(original, decrypt_file));
    }

    [TestMethod]
    public void TestFileTestAsync()
    {
        var encrypt = new Encrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var test_file_name = "testfile.dat";
        var encrypt_file_name = test_file_name + encrypt.GetExtension;

        encrypt.EncodeFileAsync(test_file_name, encrypt_file_name, Password, null, CancellationToken.None).Wait();

        var original = new FileInfo(test_file_name);

        var decrypt = new Decrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var fh = decrypt.GetFileHeader(encrypt_file_name, Password);

        Assert.AreEqual(test_file_name, fh.Name);
        Assert.AreEqual(original.CreationTime, new DateTime(fh.CreationTime));
        Assert.AreEqual(original.LastWriteTime, new DateTime(fh.LastWriteTime));

        decrypt.DecodeFileAsync(encrypt_file_name, Path.Combine(Directory.GetCurrentDirectory(), "./dec-async"),
            Password, null, CancellationToken.None).Wait();


        var decrypt_file = new FileInfo("./dec-async/" + test_file_name);

        Assert.AreEqual(true, FilesAreEqual(original, decrypt_file));
    }

    [TestMethod]
    public void TestFileZeroTest()
    {
        var encrypt = new Encrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var test_file_name = "testfile-zero.dat";
        var encrypt_file_name = test_file_name + encrypt.GetExtension;

        encrypt.EncodeFile(test_file_name, encrypt_file_name, Password);

        var original = new FileInfo(test_file_name);

        var decrypt = new Decrypt(KeySize, BlockSize, BufferSize, SaltSize);
        var fh = decrypt.GetFileHeader(encrypt_file_name, Password);

        Assert.AreEqual(test_file_name, fh.Name);
        Assert.AreEqual(original.CreationTime, new DateTime(fh.CreationTime));
        Assert.AreEqual(original.LastWriteTime, new DateTime(fh.LastWriteTime));

        decrypt.DecodeFile(encrypt_file_name, Path.Combine(Directory.GetCurrentDirectory(), "./dec"), Password);


        var decrypt_file = new FileInfo("./dec/" + test_file_name);

        Assert.AreEqual(true, FilesAreEqual(original, decrypt_file));
    }

    private bool FilesAreEqual(FileInfo first, FileInfo second)
    {
        if (first.Length != second.Length)
        {
            return false;
        }

        if (string.Equals(first.FullName, second.FullName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var iterations = (int)Math.Ceiling((double)first.Length / BytesToRead);

        using (var fs1 = first.OpenRead())
        using (var fs2 = second.OpenRead())
        {
            for (var i = 0; i < iterations; i++)
            {
                var one = ReadBytesFromStream(fs1, 0, BytesToRead);
                var two = ReadBytesFromStream(fs2, 0, BytesToRead);

                if (BitConverter.ToInt64(one, 0) != BitConverter.ToInt64(two, 0))
                {
                    return false;
                }
            }
        }

        return true;
    }

    private byte[] ReadBytesFromStream(Stream stream, int offset, int count)
    {
        using (var mem = new MemoryStream())
        {
            var totalSize = 0;
            var buf = new byte[count];
            while (totalSize < count)
            {
                var size = stream.Read(buf, offset, Math.Min(count - totalSize, buf.Length));
                if (size == 0)
                {
                    break;
                }

                mem.WriteAsync(buf, 0, size);
                totalSize += size;
            }

            return mem.ToArray();
        }
    }
}
