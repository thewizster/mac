# MAC

## A cryptographic library useful for securing communications using HMAC SHA256

### Simple example using a string as message data.
Simulate a client generating HMAC based token for the message data then sending to a server. The message is tampered with during this example.

```C#
string clientMsg = "This is a message I want to make sure is not tampered with during transport.";
string clientSecret = "secret_key"; // secret must match on both ends
Mac clientMac = new Mac(clientSecret);
var clientToken = clientMac.GenerateToken(clientMsg);

// Transport of message data and token would happen here.
// Simulate altering of data which the server would receive.
string serverMsg = "This is a message I want to make sure is not tampered with during transport. But someone has altered in transport.";

// Simulate a server receiving the message and client token then validate the data.
// Test if data has not been tampered with by generating a server side token using message and shared secret.
string serverSecret = "secret_key"; // secret must match on both ends
Mac serverMac = new Mac(serverSecret);
var serverToken = serverMac.GenerateToken(serverMsg);

// Client and server tokens match if message data has not been altered.
Assert.AreNotEqual(clientToken, serverToken); // message has been altered, tokens are not equal
```
### Example using MAC's built in Key-Value storage mechanism  
Simulate a client generating HMAC based token for key/val data and sending token and data to a server.

```C#
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
// Server side would need to extract key/val data here then add to MAC
serverMac.AddKeyVal("message", "This is some data");
serverMac.AddKeyVal("datetime", DateTime.UtcNow.ToString());
serverMac.AddKeyVal("some_other", "important data.");
var serverToken = serverMac.GenerateTokenFromKeyVal();

// Client and server tokens match if message data has not been altered.
Assert.AreEqual(clientToken, serverToken);
```