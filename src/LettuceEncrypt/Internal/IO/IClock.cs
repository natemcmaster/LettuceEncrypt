using System;

namespace LettuceEncrypt.Internal.IO
{
    internal interface IClock
    {
        DateTimeOffset Now { get; }
    }
}
