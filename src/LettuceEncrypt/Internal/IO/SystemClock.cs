using System;

namespace LettuceEncrypt.Internal.IO
{
    internal class SystemClock : IClock
    {
        public DateTimeOffset Now => DateTimeOffset.Now;
    }
}
