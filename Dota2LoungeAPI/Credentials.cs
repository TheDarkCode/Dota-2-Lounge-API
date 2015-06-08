using System.Net;

namespace SteamBotV2.Dota2LoungeAPI
{
    /// <summary>
    ///     Class to save the parameters of the login.
    /// </summary>
    public class Credentials
    {
        public string _action;
        public string _openidMode;
        public string _openidparams;
        public string _nonce;
        public string _username;
        public string _password;

        public string _auth;
        public string _remember_login;
        public string _steamid;
        public string _token;
        public string _token_secure;
        public string _webcookie;

        public CookieContainer _cookies = new CookieContainer();
    }
}
