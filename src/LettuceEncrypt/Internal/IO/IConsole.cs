// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace LettuceEncrypt.Internal.IO
{
    internal interface IConsole
    {
        bool IsInputRedirected { get; }
        ConsoleColor BackgroundColor { get; set; }
        ConsoleColor ForegroundColor { get; set; }
        bool CursorVisible { get; set; }

        void WriteLine(string line);
        void Write(string line);
        void ResetColor();
        string ReadLine();
    }
}
