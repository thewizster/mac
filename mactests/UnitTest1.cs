using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Webextant.Security.Cryptography;

namespace mactests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethodUnaltered()
        {
            // Simulate a client generating HMAC based token for the message data
            string clientMsg = "This is a message I want to make sure is not tampered with during transport.";
            string clientSecret = "secret_key"; // secret must match on both ends
            Mac clientMac = new Mac(clientSecret);
            var clientToken = clientMac.GenerateToken(clientMsg);

            // Transport of message data and token would happen here.
            string serverMsg = "This is a message I want to make sure is not tampered with during transport.";

            // Simulate a server receiving the same message and the clients token then validate the data
            // has not been tampered with by generating a server side token using message and secret.
            string serverSecret = "secret_key"; // secret must match on both ends
            Mac serverMac = new Mac(serverSecret);
            var serverToken = serverMac.GenerateToken(serverMsg);

            // Client and server tokens match if message data has not been altered.
            Assert.AreEqual(clientToken, serverToken);
        }

        [TestMethod]
        public void TestMethodAlteredData()
        {
            // Simulate a client generating HMAC based token for the message data
            string clientMsg = "This is a message I want to make sure is not tampered with during transport.";
            string clientSecret = "secret_key"; // secret must match on both ends
            Mac clientMac = new Mac(clientSecret);
            var clientToken = clientMac.GenerateToken(clientMsg);

            // Transport of message data and token would happen here.
            // Simulate altering of data which the server would receive.
            string serverMsg = "This is a message I want to make sure is not tampered with during transport. But someone has altered in transport.";

            // Simulate a server receiving the same message and the clients token then validate the data
            // has not been tampered with by generating a server side token using message and secret.
            string serverSecret = "secret_key"; // secret must match on both ends
            Mac serverMac = new Mac(serverSecret);
            var serverToken = serverMac.GenerateToken(serverMsg);

            // Client and server tokens match if message data has not been altered.
            Assert.AreNotEqual(clientToken, serverToken);
        }
        [TestMethod]
        public void TestMethodUnalteredKeyValData()
        {
            // Simulate a client generating HMAC based token for the key/val data
            string clientSecret = "secret_key"; // secret must match on both ends
            Mac clientMac = new Mac(clientSecret);
            clientMac.AddKeyVal("message", "This is some data");
            clientMac.AddKeyVal("datetime", DateTime.UtcNow.ToString());
            clientMac.AddKeyVal("some_other", "important data.");
            var clientToken = clientMac.GenerateTokenFromKeyVal();

            // Transport of data and token would happen here.

            // Simulate a server receiving the same data and the clients token then validate the data
            // has not been tampered with by generating a server side token using data and secret.
            string serverSecret = "secret_key"; // secret must match on both ends
            Mac serverMac = new Mac(serverSecret);
            serverMac.AddKeyVal("message", "This is some data");
            serverMac.AddKeyVal("datetime", DateTime.UtcNow.ToString());
            serverMac.AddKeyVal("some_other", "important data.");
            var serverToken = serverMac.GenerateTokenFromKeyVal();

            // Client and server tokens match if message data has not been altered.
            Assert.AreEqual(clientToken, serverToken);
        }
        [TestMethod]
        public void TestMethodAlteredKeyValData()
        {
            // Simulate a client generating HMAC based token for the key/val data
            string clientSecret = "secret_key"; // secret must match on both ends
            Mac clientMac = new Mac(clientSecret);
            clientMac.AddKeyVal("message", "This is some data");
            clientMac.AddKeyVal("datetime", DateTime.UtcNow.ToString());
            clientMac.AddKeyVal("some_other", "important data.");
            var clientToken = clientMac.GenerateTokenFromKeyVal();

            // Transport of data and token would happen here.
            // add 3 seconds to the time
            string tamperedDateTime = DateTime.UtcNow.AddSeconds(3).ToString();

            // Simulate a server receiving the same data and the clients token then validate the data
            // has not been tampered with by generating a server side token using data and secret.
            string serverSecret = "secret_key"; // secret must match on both ends
            Mac serverMac = new Mac(serverSecret);
            serverMac.AddKeyVal("message", "This is some data");
            serverMac.AddKeyVal("datetime", tamperedDateTime);
            serverMac.AddKeyVal("some_other", "important data.");
            var serverToken = serverMac.GenerateTokenFromKeyVal();

            // Client and server tokens match if message data has not been altered.
            Assert.AreNotEqual(clientToken, serverToken);
        }
    }
}
