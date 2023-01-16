// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace LettuceEncrypt.Internal.IO;

internal class PhysicalConsole : IConsole
{
    public static PhysicalConsole Singleton { get; } = new();

    private PhysicalConsole()
    {
    }

    public bool IsInputRedirected => Console.IsInputRedirected;

    public ConsoleColor BackgroundColor
    {
        get => Console.BackgroundColor;
        set => Console.BackgroundColor = value;
    }

    public ConsoleColor ForegroundColor
    {
        get => Console.ForegroundColor;
        set => Console.ForegroundColor = value;
    }

    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "Annotation introduced after .NET Core 3.1. Behavior is no different in .NET 6.")]
    public bool CursorVisible
    {
        get => Console.CursorVisible;
        set => Console.CursorVisible = value;
    }

    public void WriteLine(string line) => Console.WriteLine(line);
    public void Write(string line) => Console.Write(line);
    public void ResetColor() => Console.ResetColor();
    public string ReadLine() => Console.ReadLine()!;
}
