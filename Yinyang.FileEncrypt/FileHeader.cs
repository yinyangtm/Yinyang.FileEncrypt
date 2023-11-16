using System;
using System.IO;
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
    }
}
