namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
	internal interface IHttpChallengeResponseStore
	{
        void AddChallengeResponse(string token, string response);

        bool TryGetResponse(string token, out string value);
	}
}
