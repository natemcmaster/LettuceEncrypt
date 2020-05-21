// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    internal class TermsOfServiceChecker
    {
        private readonly IConsole _console;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger<TermsOfServiceChecker> _logger;

        public TermsOfServiceChecker(
            IConsole console,
            IOptions<LettuceEncryptOptions> options,
            ILogger<TermsOfServiceChecker> logger)
        {
            _console = console;
            _options = options;
            _logger = logger;
        }

        public void EnsureTermsAreAccepted(Uri termsOfServiceUri)
        {
            if (_options.Value.AcceptTermsOfService)
            {
                _logger.LogTrace("Terms of service has been accepted per configuration options");
                return;
            }

            if (!_console.IsInputRedirected)
            {
                _console.BackgroundColor = ConsoleColor.DarkBlue;
                _console.ForegroundColor = ConsoleColor.White;
                _console.WriteLine("By proceeding, you must agree with the following terms of service:");
                _console.WriteLine(termsOfServiceUri.ToString());
                _console.Write("Do you accept? [Y/n] ");
                _console.ResetColor();
                try
                {
                    _console.CursorVisible = true;
                }
                catch { }

                var result = _console.ReadLine().Trim();

                try
                {
                    _console.CursorVisible = false;
                }
                catch { }

                if (string.IsNullOrEmpty(result)
                    || string.Equals("y", result, StringComparison.OrdinalIgnoreCase)
                    || string.Equals("yes", result, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            _logger.LogError("You must accept the terms of service to continue.");
            throw new InvalidOperationException("Could not automatically accept the terms of service");
        }
    }
}
