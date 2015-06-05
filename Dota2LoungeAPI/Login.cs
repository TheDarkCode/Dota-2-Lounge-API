using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace SteamBotV2.Dota2LoungeAPI
{
    public class Login
    {
        private string username;
        private string password;
        Credentials credentials = new Credentials();

        public Login()
        {

        }
        
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

        private void getCookiesOnD2L(string url)
        {
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

            this.updateCookieContainer(this.request(url, "GET", "", "dota2lounge.com", accept, null, "", "", "", "", false));
        }

        private string postOpenIDLogin2(string location)
        {
            string referer = "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.mode=checkid_setup&openid.return_to=https%3A%2F%2Fdota2lounge.com%2Flogin&openid.realm=https%3A%2F%2Fdota2lounge.com&openid.ns.sreg=http%3A%2F%2Fopenid.net%2Fextensions%2Fsreg%2F1.1&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select";
            string accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            HttpWebResponse temp = this.request(location, "GET", referer, "dota2lounge.com", accept, null, "", "", "", "", false);
            this.updateCookieContainer(temp);
            return temp.Headers["Location"];
        }

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

        private void setSteamCredentials(DoLoginRootObject input)
        {
            credentials._auth = input.transfer_parameters.auth;
            credentials._remember_login = input.transfer_parameters.remember_login;
            credentials._steamid = input.transfer_parameters.steamid;
            credentials._token = input.transfer_parameters.token;
            credentials._token_secure = input.transfer_parameters.token_secure;
            credentials._webcookie = input.transfer_parameters.webcookie;
        }

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

        private void updateCookieContainer(HttpWebResponse inpResponse)
        {
            this.credentials._cookies.Add(inpResponse.Cookies);
        }

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

        private int GetHexVal(char hex)
        {
            int val = (int)hex;
            return val - (val < 58 ? 48 : 55);
        }

        public bool ValidateRemoteCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors policyErrors)
        {
            // allow all certificates
            return true;
        }
    }
}
