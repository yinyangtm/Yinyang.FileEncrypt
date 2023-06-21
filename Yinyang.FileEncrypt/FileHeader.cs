using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml.Serialization;

namespace Yinyang.FileEncrypt
{
    [Serializable]
    public class FileHeader
    {
        public long CreationTime { get; set; }
        public long LastAccessTime { get; set; }
        public long LastWriteTime { get; set; }
        public string Name { get; set; } = string.Empty;

        public byte[] SerializeToByteArray()
        {
            using (var ms = new MemoryStream())
            {
                var serializer = new XmlSerializer(typeof(FileHeader));
                serializer.Serialize(ms, this);
                return ms.ToArray();
            }
        }

        public static FileHeader Deserialize(byte[] byteArray)
        {
            using (var memStream = new MemoryStream(byteArray))
            {
                var serializer = new XmlSerializer(typeof(FileHeader));
                var obj = (FileHeader) serializer.Deserialize(memStream);
                return obj;
            }
        }

        public byte[] ObjectToByteArray()
        {
            var bf = new BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                bf.Serialize(ms, this);
                return ms.ToArray();
            }
        }

        public static FileHeader ByteArrayToObject(byte[] arrBytes)
        {
            using (var memStream = new MemoryStream())
            {
                var binForm = new BinaryFormatter();
                memStream.Write(arrBytes, 0, arrBytes.Length);
                memStream.Seek(0, SeekOrigin.Begin);
                var obj = binForm.Deserialize(memStream) as FileHeader ?? throw new FormatException();
                return obj;
            }
        }
    }
}
