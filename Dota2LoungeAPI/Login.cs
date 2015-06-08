using Newtonsoft.Json;
using System;
using System.Collections.Specialized;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace SteamBotV2.Dota2LoungeAPI
{
    /// <summary>
    ///     Class of www.dota2lounge.com Login procedure.
    /// </summary>
    public class Login
    {
        private string username;
        private string password;
        Credentials credentials = new Credentials();

        //Constructors
        /// <summary>
        ///     Empty Constructor
        /// </summary>
        public Login()
        {

        }
        

        //Login methods
        /// <summary>
        ///     Method to start the login without gmail email handler.
        /// </summary>
        /// <param name="username">Username of your steam account.</param>
        /// <param name="password">Password of your steam account.</param>
        public void doLogin(string username, string password)
        {
            this.username = username;
            this.password = password;
            this.getOpenidLogin();
            GetRsaKey temp = this.getRSAKey();
            this.loginDoLogin(temp, "");
            temp = this.getRSAKey();
            string steamGuardText = "";
            Console.WriteLine("Type Steam Guard: ");
            steamGuardText = Uri.EscapeDataString(Console.ReadLine());
            this.setSteamCredentials(JsonConvert.DeserializeObject<DoLoginRootObject>(
                this.getResponseMessage(this.loginDoLogin(temp, steamGuardText))));
            this.postTransfer();
            this.getCookiesOnD2L(this.postOpenIDLogin2(this.postOpenIDLogin()));
        }

        /// <summary>
        ///     Method to start the login with gmail email handler.
        ///     This method will only work if your steam account is registered with an gmail
        ///     account. If you have another Email provider, then use:
        ///     doLogin(string username, string password);
        /// </summary>
        /// <param name="username">Username of your steam account.</param>
        /// <param name="password">Password of your steam account.</param>
        /// <param name="emailAddress">Email address of your gmail account.</param>
        /// <param name="emailPassword">Password of your gmail account.</param>
        public void doLogin(string username, string password, string emailAddress, string emailPassword)
        {
            this.username = username;
            this.password = password;
            this.getOpenidLogin();
            GetRsaKey temp = this.getRSAKey();
            this.loginDoLogin(temp, "");
            temp = this.getRSAKey();
            string steamGuardText = "";
            EMailHandler e = new EMailHandler(emailAddress, emailPassword);
            steamGuardText = e.getGuardText();
            System.Threading.Thread.Sleep(2500);
            this.setSteamCredentials(JsonConvert.DeserializeObject<DoLoginRootObject>(
                this.getResponseMessage(this.loginDoLogin(temp, steamGuardText))));
            this.postTransfer();
            this.getCookiesOnD2L(this.postOpenIDLogin2(this.postOpenIDLogin()));
        }

        
        //Formal Requests and Response Parsing
        /// <summary>
        ///     The formal method to use HTTPWebRequests.
        ///     I got the headers out of Fiddler. I highly recommend this tool to follow HTTPWebRequests.
        ///     Some Headers are unnecessary but i will use them for a natural-looking HTTPWebRequests.
        /// </summary>
        /// <param name="inpUrl">URL of the HTTPWebRequest.</param>
        /// <param name="inpMethod">Method of the HTTPWebRequest.
        ///     Example: "POST", "GET", "PUT",...</param>
        /// <param name="inpReferer">The Referer of the URL. Sometimes its needed.</param>
        /// <param name="inpHost">The Host of the request.</param>
        /// <param name="inpAccept">Accept format of the request.</param>
        /// <param name="inpNVC">Data which will be wrote if you will do a "Post".</param>
        /// <param name="xRequestedWith">If Ajax, then this is required.</param>
        /// <param name="xPrototypeVersion">If Ajax, then this is required.</param>
        /// <param name="cacheControl">Says, if the request controlls the Cache.</param>
        /// <param name="pragma">Pragma argument.</param>
        /// <param name="allowAutoRedirect">This will desribe, if the request allows to auto-redirect.</param>
        /// <returns>A HttpWebResponse of the request.</returns>
        private HttpWebResponse request(string inpUrl, string inpMethod, string inpReferer, string inpHost, string inpAccept, NameValueCollection inpNVC, string xRequestedWith, string xPrototypeVersion,
            string cacheControl, string pragma, bool allowAutoRedirect)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(inpUrl);
            request.Accept = inpAccept;
            request.AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip;
            request.UserAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36";
            request.Timeout = 10000;
            request.Headers.Add("Accept-Language", "de,en-US;q=0.7,en;q=0.3");

            request.AllowAutoRedirect = allowAutoRedirect;

            request.CookieContainer = credentials._cookies;

            request.Method = inpMethod;

            //Volatile variables

            if (inpHost != "")
            {
                request.Host = inpHost;
            }

            if (inpReferer != "")
            {
                request.Referer = inpReferer;
            }

            if (xRequestedWith != "")
            {
                request.Headers.Add("X-Requested-With", xRequestedWith);
            }

            if (xPrototypeVersion != "")
            {
                request.Headers.Add("X-Prototype-Version", xPrototypeVersion);
            }

            if (cacheControl != "")
            {
                request.Headers.Add("Cache-Control", cacheControl);
            }

            if (pragma != "")
            {
                request.Headers.Add("Pragma", pragma);
            }

            if (inpMethod == "POST")
            {
                string dataString = (inpNVC == null ? null : String.Join("&", Array.ConvertAll(inpNVC.AllKeys, key =>
                String.Format("{0}={1}", HttpUtility.UrlEncode(key), HttpUtility.UrlEncode(inpNVC[key]))
                )));
                byte[] dataBytes = Encoding.UTF8.GetBytes(dataString);
                request.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                request.ContentLength = dataBytes.Length;
                using (Stream requestStream = request.GetRequestStream())
                {
                    requestStream.Write(dataBytes, 0, dataBytes.Length);
                }
            }

            return request.GetResponse() as HttpWebResponse;
        }

        /// <summary>
        ///     This method will parse a String out of an HTTPWebResponse.
        /// </summary>
        /// <param name="inpResponse">The HTTPWebResponse to be parsed.</param>
        /// <returns>The Body of the HTTPWebRequest.</returns>
        private String getResponseMessage(HttpWebResponse inpResponse)
        {
            string result = "";
            using (inpResponse)
            {
                using (Stream responseStream = inpResponse.GetResponseStream())
                {
                    using (StreamReader reader = new StreamReader(responseStream))
                    {
                        result += reader.ReadToEnd();
                    }
                }
            }
            return result;
        }

        /// <summary>
        ///     This method will update the CookieContainer in the Credentials.cs Object.
        ///     This requires a HTTPWebResponse because in there, there are the Cookies which are
        ///     required for further requests.
        /// </summary>
        /// <param name="inpResponse"></param>
        private void updateCookieContainer(HttpWebResponse inpResponse)
        {
            this.credentials._cookies.Add(inpResponse.Cookies);
        }


        //Special Requests
        /// <summary>
        ///     First Request of the D2L Login. Here this method will get the OpenID parameters.
        /// </summary>
        private void getOpenidLogin()
        {
            string url = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string referer = "http://dota2lounge.com/";
            string host = "steamcommunity.com";
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            HttpWebResponse response = this.request(url, "GET", referer, host, accept, null, "", "", "", "", true);
            this.updateCookieContainer(response);
            string output = this.getResponseMessage(response);
            this.setOpenidParam(output);
        }

        /// <summary>
        ///     Get the RSA Key out of the steam site.
        /// </summary>
        /// <returns>An JSON-Deserialized Object with some parameters.</returns>
        private GetRsaKey getRSAKey()
        {
            var data = new NameValueCollection();
            data.Add("username", this.username);

            string url = "https://steamcommunity.com/login/getrsakey/";
            string referer = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string host = "steamcommunity.com";
            string accept = "text/javascript, text/html, application/xml, text/xml, */*";
            HttpWebResponse response = this.request(url, "POST", referer, host, accept, data, "XMLHttpRequest", "1.7", "no-cache", "no-cache", false);
            this.updateCookieContainer(response);
            string result = this.getResponseMessage(response);
            return JsonConvert.DeserializeObject<GetRsaKey>(result);
        }

        /// <summary>
        ///     Do the login with the RSA encrypted password.
        /// </summary>
        /// <param name="inputResponse">This is the JSON-Deserialized Object out of the RSA Response of Steam.
        ///     In this object is the RSA key to encrypt the password.</param>
        /// <param name="guardText">This is an parameter if steam guard is activated, steam will send a key
        /// to your Email to check and paste in.</param>
        /// <returns>THis request returns a response which will be parsed, if the login was correct.</returns>
        private HttpWebResponse loginDoLogin(GetRsaKey inputResponse, string guardText)
        {
            var data = new NameValueCollection();
            data.Add("remember_login", "false");

            data.Add("captchagid", "-1");
            data.Add("password", this.getEncryptedBase64Password(inputResponse));
            data.Add("twofactorcode", "");
            data.Add("captcha_text", "");
            data.Add("username", this.username);

            if (inputResponse.timestamp != null)
            {
                data.Add("rsatimestamp", inputResponse.timestamp.ToString());
            }
            else
            {
                data.Add("rsatimestamp", "");
            }

            if (guardText == "")
            {
                data.Add("emailauth", "");
                data.Add("emailsteamid", "");
                data.Add("loginfriendlyname", "");
            }
            else
            {
                data.Add("emailauth", guardText);
                data.Add("emailsteamid", inputResponse.steamid);
                data.Add("loginfriendlyname", guardText + "a");
            }

            string referer = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string url = "https://steamcommunity.com/login/dologin/";
            string host = "steamcommunity.com";
            string accept = "text/javascript, text/html, application/xml, text/xml, */*";

            HttpWebResponse response = this.request(url, "POST", referer, host, accept, data, "XMLHttpRequest", "1.7", "", "", false);
            this.updateCookieContainer(response);
            return response;
        }

        /// <summary>
        ///     Just the postTransfer request.
        /// </summary>
        private void postTransfer()
        {
            var data = new NameValueCollection();
            data.Add("auth", credentials._auth);
            data.Add("remember_login", credentials._remember_login);
            data.Add("steamid", credentials._steamid);
            data.Add("token", credentials._token);
            data.Add("token_secure", credentials._token_secure);
            data.Add("webcookie", credentials._webcookie);

            string url = "https://store.steampowered.com/login/transfer";
            string referer = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            this.updateCookieContainer(this.request(url, "POST", referer, "", accept, data, "", "", "", "", false));
        }

        /// <summary>
        ///     This is the Open ID authorization by the site you are logging in through steam.
        /// </summary>
        /// <returns>The location (redirect url).</returns>
        private string postOpenIDLogin()
        {
            var data = new NameValueCollection();
            data.Add("action", credentials._action);
            data.Add("openid.mode", credentials._openidMode);
            data.Add("openidparams", credentials._openidparams);
            data.Add("nonce", credentials._nonce);

            string url = "https://steamcommunity.com/openid/login";
            string referer = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            HttpWebResponse temp = this.request(url, "POST", referer, "", accept, data, "", "", "", "", false);
            this.updateCookieContainer(temp);
            return temp.Headers["Location"];
        }

        /// <summary>
        ///     Second step to authoritize.
        /// </summary>
        /// <param name="location">URL to connect.</param>
        /// <returns>Another location to redirect.</returns>
        private string postOpenIDLogin2(string location)
        {
            string referer = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            HttpWebResponse temp = this.request(location, "GET", referer, "dota2lounge.com", accept, null, "", "", "", "", false);
            this.updateCookieContainer(temp);
            return temp.Headers["Location"];
        }

        /// <summary>
        ///     Get final Cookies on Dota2lounge. This will be required to do further requests to this site.
        /// </summary>
        /// <param name="url">The location returned after the Open ID login process.</param>
        private void getCookiesOnD2L(string url)
        {
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            this.updateCookieContainer(this.request(url, "GET", "", "dota2lounge.com", accept, null, "", "", "", "", false));
        }

     
        //Help Methods, parse Data and encrypt Data
        /// <summary>
        ///     This method will set the Steam credentials.
        /// </summary>
        /// <param name="input">Input object of the JSON-Deserialized object.</param>
        private void setSteamCredentials(DoLoginRootObject input)
        {
            credentials._auth = input.transfer_parameters.auth;
            credentials._remember_login = input.transfer_parameters.remember_login;
            credentials._steamid = input.transfer_parameters.steamid;
            credentials._token = input.transfer_parameters.token;
            credentials._token_secure = input.transfer_parameters.token_secure;
            credentials._webcookie = input.transfer_parameters.webcookie;
        }

        /// <summary>
        ///     Method to get the encrypted Password after RSA encryption.
        /// </summary>
        /// <param name="input">The RSA object out of the JSON response.</param>
        /// <returns>The encrypted password.</returns>
        private string getEncryptedBase64Password(GetRsaKey input)
        {
            //RSA Encryption
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAParameters rsaParameters = new RSAParameters();

            rsaParameters.Exponent = HexToByte(input.publickey_exp);
            rsaParameters.Modulus = HexToByte(input.publickey_mod);

            rsa.ImportParameters(rsaParameters);

            byte[] bytePassword = Encoding.ASCII.GetBytes(this.password);
            byte[] encodedPassword = rsa.Encrypt(bytePassword, false);
            string encryptedBase64Password = Convert.ToBase64String(encodedPassword);

            return encryptedBase64Password;
        }

        /// <summary>
        ///     Set the Open ID params.
        /// </summary>
        /// <param name="input">Response from the first response.</param>
        private void setOpenidParam(string input)
        {
            String[] temp = Regex.Split(input, "<input type=\"hidden\" id=\"actionInput\" name=\"action\" value=\"");
            String[] temp1 = Regex.Split(temp[1], "\" />\r\n\t\t\t\t\t\t\t\t\t\t\t<input type=\"hidden\" name=\"openid.mode\" value=\"");
            String[] temp2 = Regex.Split(temp1[1], "\" />\r\n\t\t\t\t\t\t<input type=\"hidden\" name=\"openidparams\" value=\"");
            String[] temp3 = Regex.Split(temp2[1], "\" />\r\n\t\t\t\t\t\t\t\t\t\t<input type=\"hidden\" name=\"nonce\" value=\"");
            String[] temp4 = Regex.Split(temp3[1], "\"");
            this.credentials._action = temp1[0];
            this.credentials._openidMode = temp2[0];
            this.credentials._openidparams = temp3[0];
            this.credentials._nonce = temp4[0];
        }

        /// <summary>
        ///     Small Hex to Byte Method.
        /// </summary>
        /// <param name="hex">Input hex.</param>
        /// <returns>A variable from type byte[]</returns>
        private byte[] HexToByte(string hex)
        {
            if (hex.Length % 2 == 1)
                throw new Exception("The binary key cannot have an odd number of digits");

            byte[] arr = new byte[hex.Length >> 1];
            int l = hex.Length;

            for (int i = 0; i < (l >> 1); ++i)
            {
                arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
            }

            return arr;
        }

        /// <summary>
        ///     Get the Hex Value of hex.
        /// </summary>
        /// <param name="hex">Hex variable.</param>
        /// <returns>A simple integer.</returns>
        private int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : 55);
        }

        /// <summary>
        ///     Just a method to accept X509Certificate.
        /// </summary>
        /// <param name="sender">Sender parameter.</param>
        /// <param name="certificate">Certificate parameter.</param>
        /// <param name="chain">Chain parameter.</param>
        /// <param name="policyErrors">Policy parameter.</param>
        /// <returns>A true value to accepts this certificate</returns>
        private bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors policyErrors)
        {
            // allow all certificates
            return true;
        }

        /// <summary>
        ///     Method to get the credentials after the Login.
        /// </summary>
        /// <returns>A credentials object(/Dota2LoungeAPI/Credentials.cs).</returns>
        public Credentials getCredentials()
        {
            if (this.credentials != null)
            {
                return this.credentials;
            }
            else
            {
                throw new System.Exception("Login ended not successful.");
                return null;
            }
        }
    }
}
