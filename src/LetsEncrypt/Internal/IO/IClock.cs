using System;

namespace McMaster.AspNetCore.LetsEncrypt.Internal.IO
{
    internal interface IClock
    {
        DateTimeOffset Now { get; }
    }
}
