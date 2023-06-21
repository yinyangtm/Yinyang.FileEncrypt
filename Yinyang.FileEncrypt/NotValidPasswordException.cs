using System;
using System.Runtime.Serialization;

namespace Yinyang.FileEncrypt
{
    [Serializable]
    public class NotValidPasswordException : Exception
    {
        public NotValidPasswordException()
        {
        }

        public NotValidPasswordException(string message)
            : base(message)
        {
        }

        public NotValidPasswordException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected NotValidPasswordException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
