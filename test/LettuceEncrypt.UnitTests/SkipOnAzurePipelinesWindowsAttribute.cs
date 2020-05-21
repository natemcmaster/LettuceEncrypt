using System;
using System.Runtime.InteropServices;
using McMaster.Extensions.Xunit;

namespace LettuceEncrypt.UnitTests
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal class SkipOnAzurePipelinesWindowsAttribute : Attribute, ITestCondition
    {
        public bool IsMet => string.IsNullOrEmpty(Environment.GetEnvironmentVariable("TF_BUILD"))
            || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public string SkipReason { get; set; }
    }
}
