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
    public class EMailHandler
    {
        private string user;
        private string password;
        public EMailHandler(string inpEmail, string inpPassword)
        {
            this.user = inpEmail;
            this.password = inpPassword;
        }
        public string getSteamCode()
        {
            string x = getMessage("pop.gmail.com", 995, true, user, password);
            if (x.Equals("0 _*_")) 
            {
                //Console.WriteLine("FEHLER");
                throw new System.InvalidOperationException("EMail ist noch nicht da...");
            }
            else
            {
                return x;
            }
        }

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

            
            /*
            int number = 0;

            foreach (string line in lines)
            {
                number += 1;
            }
            string neu = lines[16];


            number = 0;
            string[] words = neu.Split(' ');
            foreach (string word in words)
            {
                number += 1;
            }

            string Guard = words[8];
            return Guard;*/
        }
    }
}
