// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if NETSTANDARD2_0
// This code doesn't do anything, but makes C# 8 play nice with netstandard2.0 without
// having to have a bunch of #if defs all over the place.

namespace System.Diagnostics.CodeAnalysis
{
    internal class MaybeNullWhenAttribute : Attribute
    {
        public MaybeNullWhenAttribute(bool returnValue)
        {
            ReturnValue = returnValue;
        }

        public bool ReturnValue { get; }
    }
}
#endif
