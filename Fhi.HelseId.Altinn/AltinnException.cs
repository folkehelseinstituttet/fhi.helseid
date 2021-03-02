using System;
using System.Runtime.Serialization;

namespace Fhi.HelseId.Altinn
{
    [Serializable]
    public class AltinnException : Exception
    {
        public AltinnException()
        {
        }

        public AltinnException(string? message) : base(message)
        {
        }

        public AltinnException(string? message, Exception? innerException) : base(message, innerException)
        {
        }

        protected AltinnException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}