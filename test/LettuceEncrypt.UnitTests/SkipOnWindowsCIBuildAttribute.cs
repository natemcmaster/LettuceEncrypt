using System;
using System.Runtime.InteropServices;
using McMaster.Extensions.Xunit;

namespace LettuceEncrypt.UnitTests
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
    internal class SkipOnWindowsCIBuildAttribute : Attribute, ITestCondition
    {
        public bool IsMet => string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI"))
                             || !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        public string SkipReason { get; set; }
    }
}
