using System;

namespace McMaster.AspNetCore.LetsEncrypt.Internal.IO
{
    internal class SystemClock : IClock
    {
        public DateTimeOffset Now => DateTimeOffset.Now;
    }
}
