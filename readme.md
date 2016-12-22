# Mac.NET

## A cryptographic library useful for securing communications using HMAC(SHA256)

### Why Mac.NET

Provides a simple and easy to use wrapper class which enables developers to quickly add Hash-based Message Authentication Code (HMAC) to help secure messaging systems and web services. Built for modern .NET Core apps.

### CLI Quickstart

This quickstart builds on the sample hello console app that is created using the .NET Core CLI tool.

#### Tools you will need installed
.NET Core https://www.microsoft.com/net/core  
Text editor of choice or Visual Studio Code https://code.visualstudio.com/

1) Create a folder for a new .NET Core app: `mkdir hellomac && cd hellomac`  
2) Inside the hellomac folder create a new .NET Core application: `dontnet new`  
3) Edit the project.json file. Add to dependencies section: `"Webextant.Security.Cryptography.Mac":"1.0.2"`  
4) Restore packages: `dotnet restore`  
5) At top of Program.cs file add `using Webextant.Security.Cryptography;` after `using System;`  
6) Edit the Program.cs file replacing the `Console.WriteLine("Hello World!")` code with.  

```C#
string clientMsg = "A Fool and His Money Are Soon Parted";
string clientSecret = "secret_key"; // secret must match on both ends
Mac clientMac = new Mac(clientSecret);
var clientToken = clientMac.GenerateToken(clientMsg);

// Transport of message data and token would happen here.
Console.WriteLine("Client Token: {0}", clientToken);

// Simulate a server receiving the message and the client token then validate the data.
// Test if data has not been tampered with by generating a server side token using received message and shared secret.
string serverMsg = "Don't count your chickens before they are hatched";
string serverSecret = "secret_key"; // secret must match on both ends
Mac serverMac = new Mac(serverSecret);
var serverToken = serverMac.GenerateToken(serverMsg);
Console.WriteLine("Server Token: {0}", serverToken);

// Do the client and server token match?
Console.WriteLine("Tokens Match: {0}", clientToken == serverToken);
```

7) Build and run: `dotnet build && dotnet run`

### NuGet Package
https://www.nuget.org/packages/Webextant.Security.Cryptography.Mac/

### Other Examples

#### Simple example using a string as message data.
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
#### Example using MAC's built in Key-Value storage mechanism  
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

### What is HMAC
https://en.wikipedia.org/wiki/Hash-based_message_authentication_code

### Who is using HMAC
https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/authentication-for-the-azure-storage-services
http://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/HMACAuth.html
https://developers.google.com/maps/documentation/directions/get-api-key#client-id
