using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using OpenPop.Common;
using OpenPop.Mime;
using OpenPop.Pop3;

using System.Text.RegularExpressions;

namespace SteamBotV2
{
    /// <summary>
    ///     Class to get the steam guard code from gmail.
    /// </summary>
    public class EMailHandler
    {
        private string user;
        private string password;

        /// <summary>
        ///     Public Constructor of the class EMailHandler.
        /// </summary>
        /// <param name="inpEmail">EMail of the GMail Account.</param>
        /// <param name="inpPassword">Password of the GMail Account.</param>
        public EMailHandler(string inpEmail, string inpPassword)
        {
            this.user = inpEmail;
            this.password = inpPassword;
        }

        /// <summary>
        ///     Get the Steam Code.
        /// </summary>
        /// <returns>Returns the message of Steam.</returns>
        public string getSteamCode()
        {
            string x = getMessage("pop.gmail.com", 995, true, user, password);
            if (x.Equals("0 _*_")) 
            {
                //Console.WriteLine("FEHLER");
                throw new System.InvalidOperationException("EMail is not sent.");
            }
            else
            {
                return x;
            }
        }

        /// <summary>
        ///     Get a message from POP-mail.
        /// </summary>
        /// <param name="hostname">Hostname.</param>
        /// <param name="port">Port.</param>
        /// <param name="useSsl">Is SSL used?</param>
        /// <param name="username">Username of POP.</param>
        /// <param name="password">Password of POP.</param>
        /// <returns></returns>
        public static string getMessage(string hostname, int port, bool useSsl, string username, string password)
        {
            // The client disconnects from the server when being disposed
            using (Pop3Client client = new Pop3Client())
            {
                // Connect to the server
                client.Connect(hostname, port, useSsl);

                // Authenticate ourselves towards the server
                client.Authenticate(username, password);
                // Get the number of messages in the inbox
                int messageCount = client.GetMessageCount();
                string result = string.Empty;

                if (messageCount != 0 && client.GetMessage(1).Headers.From.Address.Equals("noreply@steampowered.com"))
                {
                    result = client.GetMessage(1).FindFirstPlainTextVersion().GetBodyAsText();
                }
                result = messageCount + " _*_" + result;
                client.DeleteAllMessages();
                return result;
            }
        }

        /// <summary>
        ///     Get the exact five-digit Steam Guard Code.
        /// </summary>
        /// <returns>A String of the Steam Guard Code.</returns>
        public string getGuardText()
        {
            string s = string.Empty;
            string Guard = "";
            try
            {
                s = getSteamCode();
                string[] lines = Regex.Split(s, "\r\n");

                Guard = lines[5];
                
            }
            catch (InvalidOperationException ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {

            }
            return Guard;
        }
    }
}
